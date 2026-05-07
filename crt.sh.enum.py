#!/usr/bin/env python3
"""
Enumerate subdomains from crt.sh certificate transparency logs via PostgreSQL.
Fetches Common Names (CN) and Subject Alternative Names (SANs).

Sources queried per certificate (all filtered to target domain):
  1. commonName (2.5.4.3) and dNSName SANs (san:dNSName)
  2. rfc822Name SANs (san:rfc822Name)     — domain extracted after '@'
  3. URI SANs (san:uniformResourceIdentifier) — hostname extracted from URI
  4. CRL Distribution Point URLs          — hostname extracted from URL
  5. Authority Information Access URLs    — hostname extracted from URL

Query strategy:
  Phase 1 — fetch ALL matching cert IDs in one shot using the GIN index on
  identities(certificate) via to_tsquery('certwatch', reverse(domain) || ':*').
  No ORDER BY or LIMIT is used so the planner stays on the GIN bitmap path.

  Phase 2 — extract all 5 name sources for each batch of BATCH_SIZE cert IDs.
  New unique names are written to output immediately after each batch so results
  appear progressively. Splitting name extraction into small batches keeps each
  query within the server's statement_timeout even for large domains.

  Note: crt.sh runs PgBouncer in statement pooling mode. Recovery conflicts on
  the hot-standby drop the TCP connection, so each retry opens a fresh connection.
  Very large domains (e.g. google.com) may have too many certificates for Phase 1
  to complete within the server's statement_timeout.
"""

import argparse
import sys
import time
from typing import IO, List, Optional, Set

try:
    import psycopg2
except ImportError:
    print("Error: 'psycopg2-binary' is required — install with: pip install psycopg2-binary", file=sys.stderr)
    sys.exit(1)

PG_HOST = "crt.sh"
PG_PORT = 5432
PG_USER = "guest"
PG_DBNAME = "certwatch"
PG_CONNECT_TIMEOUT = 60

_URL_HOST_RE = r'[a-z][a-z0-9+.\-]*://([^/:?# ]+)'

_MAX_RETRIES = 5
_RETRY_DELAY = 10
_BATCH_SIZE = 500

# Phase 1: collect all matching cert IDs via GIN index (no ORDER BY so the
# planner stays on the GIN bitmap path instead of a sequential id-order scan).
_ALL_IDS_QUERY = """
SELECT id
FROM certificate
WHERE identities(certificate) @@ to_tsquery('certwatch', reverse(lower(%(domain)s)) || ':*')
"""

# Phase 2: extract all 5 name sources for a bounded set of cert IDs.
_NAMES_QUERY = """
-- 1. commonName and dNSName SANs
SELECT DISTINCT lower(ci.name_value) AS name
FROM certificate_and_identities ci
WHERE ci.certificate_id = ANY(%(ids)s)
  AND ci.name_type IN ('2.5.4.3', 'san:dNSName')
  AND (
      lower(ci.name_value) = %(domain)s
      OR lower(ci.name_value) LIKE %(like_sub)s
  )

UNION

-- 2. rfc822Name SANs: extract the domain half of the email address
SELECT DISTINCT split_part(lower(ci.name_value), '@', 2) AS name
FROM certificate_and_identities ci
WHERE ci.certificate_id = ANY(%(ids)s)
  AND ci.name_type = 'san:rfc822Name'
  AND (
      split_part(lower(ci.name_value), '@', 2) = %(domain)s
      OR split_part(lower(ci.name_value), '@', 2) LIKE %(like_sub)s
  )

UNION

-- 3. URI SANs: extract hostname from the URI value
SELECT DISTINCT (regexp_match(lower(ci.name_value), %(url_host_re)s))[1] AS name
FROM certificate_and_identities ci
WHERE ci.certificate_id = ANY(%(ids)s)
  AND ci.name_type = 'san:uniformResourceIdentifier'
  AND lower(ci.name_value) LIKE %(like_url)s
  AND (regexp_match(lower(ci.name_value), %(url_host_re)s))[1] IS NOT NULL

UNION

-- 4. CRL Distribution Points: extract hostname from each CRL URL
SELECT DISTINCT (regexp_match(lower(cdp), %(url_host_re)s))[1] AS name
FROM certificate c
CROSS JOIN LATERAL x509_crldistributionpoints(c.certificate) AS cdp
WHERE c.id = ANY(%(ids)s)
  AND lower(cdp) LIKE %(like_url)s
  AND (regexp_match(lower(cdp), %(url_host_re)s))[1] IS NOT NULL

UNION

-- 5. Authority Information Access: extract hostname from OCSP / CA issuer URLs
SELECT DISTINCT (regexp_match(lower(aia), %(url_host_re)s))[1] AS name
FROM certificate c
CROSS JOIN LATERAL x509_authorityinfoaccess(c.certificate) AS aia
WHERE c.id = ANY(%(ids)s)
  AND lower(aia) LIKE %(like_url)s
  AND (regexp_match(lower(aia), %(url_host_re)s))[1] IS NOT NULL
"""


def _connect(verbose: bool) -> "psycopg2.connection":
    if verbose:
        print(f"[INFO] Connecting to postgresql://{PG_HOST}:{PG_PORT}...", file=sys.stderr)
    conn = psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        user=PG_USER,
        dbname=PG_DBNAME,
        connect_timeout=PG_CONNECT_TIMEOUT,
    )
    conn.autocommit = True
    return conn


def _run_query(
    conn: "psycopg2.connection",
    query: str,
    params: dict,
    context: str,
    verbose: bool,
) -> "tuple[List, psycopg2.connection]":
    """Run a single query on *conn*, reconnecting on recovery conflicts. Returns (rows, conn)."""
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            with conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchall(), conn
        except Exception as exc:
            exc_str = str(exc)
            if "conflict with recovery" in exc_str and attempt < _MAX_RETRIES:
                print(
                    f"[!] Recovery conflict during {context} (attempt {attempt}/{_MAX_RETRIES}),"
                    f" retrying in {_RETRY_DELAY}s...",
                    file=sys.stderr,
                )
                try:
                    conn.close()
                except Exception:
                    pass
                time.sleep(_RETRY_DELAY)
                conn = _connect(verbose)
                continue
            raise
    return [], conn


def enumerate_domain(domain: str, verbose: bool, out_fh: IO[str], seen: Set[str]) -> int:
    """
    Query crt.sh for all names under *domain*, write new unique names to
    *out_fh* immediately after each batch, and update *seen* in place.
    Returns the count of new names found for this domain.
    """
    domain = domain.lower().strip().lstrip("*.")
    if verbose:
        print(f"[INFO] Querying crt.sh for: {domain}", file=sys.stderr)

    base_params = {
        "domain": domain,
        "like_sub": f"%.{domain}",
        "like_url": f"%.{domain}%",
        "url_host_re": _URL_HOST_RE,
    }

    conn = _connect(verbose)
    try:
        # Phase 1: get all matching cert IDs.
        if verbose:
            print("[INFO] Fetching matching certificates...", file=sys.stderr)

        try:
            id_rows, conn = _run_query(conn, _ALL_IDS_QUERY, {"domain": domain}, "certificate fetch", verbose)
        except Exception as exc:
            exc_str = str(exc)
            if "statement timeout" in exc_str:
                print(
                    "[!] Query timed out — the server's statement_timeout was exceeded.\n"
                    "    Very large domains (e.g. google.com) have too many certificates\n"
                    "    for the guest account to query within the server's time limit.",
                    file=sys.stderr,
                )
            else:
                print(f"[!] PostgreSQL error: {exc}", file=sys.stderr)
            return 0

        all_ids = [row[0] for row in id_rows]
        if not all_ids:
            print(f"[+] 0 unique names found for {domain}", file=sys.stderr)
            return 0

        if verbose:
            print(f"[INFO] Found {len(all_ids)} matching certificates...", file=sys.stderr)

        # Phase 2: extract names in batches, writing new results immediately.
        domain_count = 0
        for batch_start in range(0, len(all_ids), _BATCH_SIZE):
            batch_ids = all_ids[batch_start:batch_start + _BATCH_SIZE]
            batch_num = batch_start // _BATCH_SIZE + 1

            if verbose:
                print(
                    f"[INFO] Extracting domains from certificates"
                    f" {batch_start + 1}–{batch_start + len(batch_ids)} of {len(all_ids)}...",
                    file=sys.stderr,
                )

            try:
                name_rows, conn = _run_query(
                    conn, _NAMES_QUERY, {**base_params, "ids": batch_ids},
                    f"names batch {batch_num}", verbose,
                )
            except Exception as exc:
                exc_str = str(exc)
                if "statement timeout" in exc_str:
                    print(
                        f"[!] Names batch {batch_num} timed out — {domain_count} names written so far.",
                        file=sys.stderr,
                    )
                else:
                    print(f"[!] PostgreSQL error (names batch {batch_num}): {exc}", file=sys.stderr)
                break

            new_names = []
            for (name,) in name_rows:
                if not name:
                    continue
                name = name.strip().lower().lstrip("*.")
                if name and (name == domain or name.endswith(f".{domain}")) and name not in seen:
                    seen.add(name)
                    new_names.append(name)

            if new_names:
                new_names.sort()
                out_fh.write("\n".join(new_names) + "\n")
                out_fh.flush()
                domain_count += len(new_names)

            if verbose:
                print(f"[INFO] {len(new_names)} new domains found (total: {domain_count})", file=sys.stderr)

    finally:
        try:
            conn.close()
        except Exception:
            pass

    print(f"[+] {domain_count} unique names found for {domain}", file=sys.stderr)
    return domain_count


def _load_domain_file(path: str) -> List[str]:
    """Read a newline-separated domain list, stripping blanks and comments."""
    try:
        with open(path) as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except OSError as exc:
        print(f"[!] Cannot read domain file '{path}': {exc}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enumerate CNs and SANs from crt.sh certificate transparency logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s example.com\n"
            "  %(prog)s example.com another.com\n"
            "  %(prog)s -d domains.txt\n"
            "  %(prog)s example.com -d domains.txt -v -o results.txt\n"
        ),
    )
    parser.add_argument("domains", nargs="*", help="Domain(s) to enumerate")
    parser.add_argument(
        "-d", "--domains",
        dest="file",
        metavar="FILE",
        help="File containing newline-separated domains to enumerate",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print connection and query progress messages",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write results to FILE instead of stdout",
    )

    args = parser.parse_args()

    domains = list(args.domains)
    if args.file:
        domains.extend(_load_domain_file(args.file))

    if not domains:
        parser.error("at least one domain is required (via argument or -f/--file)")

    out_fh = open(args.output, "w") if args.output else sys.stdout
    seen: Set[str] = set()
    total = 0

    try:
        for domain in domains:
            total += enumerate_domain(domain, args.verbose, out_fh, seen)
    finally:
        if args.output:
            out_fh.close()

    if total == 0:
        print("[!] No results found.", file=sys.stderr)
        sys.exit(1)

    if args.output:
        print(f"[+] Wrote {total} names to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
