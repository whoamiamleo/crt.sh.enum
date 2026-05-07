# crt.sh.enum

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-psycopg2-336791?style=flat-square&logo=postgresql&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)
![Authorized Pentesting Only](https://img.shields.io/badge/⚠%EF%B8%8F%20Authorized%20Pentesting%20Only-critical?style=flat-square)

Subdomain enumeration via [crt.sh](https://crt.sh) certificate transparency logs, using a direct PostgreSQL connection for fast, uninterrupted queries.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
  - [Examples](#examples)
- [Support](#support)
- [Formatting](#formatting)
  - [Input](#input)
  - [Output](#output)
- [Contributing](#contributing)
- [Attribution](#attribution)
- [Legal & Ethics](#legal--ethics)
- [License](#license)

---

## Features

- **Direct PostgreSQL access**: Connects directly to crt.sh's public read replica database, bypassing the rate-limited HTTP API for faster and more complete queries.
- **Five name sources per certificate**: Extracts Common Name, dNSName SANs, email SANs, URI SANs, and CRL/AIA hostnames for maximum coverage.
- **Batch processing**: Queries certificates in batches of 500 to stay within server timeouts, with results streamed progressively.
- **Auto-retry**: Automatically reconnects and retries up to 5 times on database connection failures caused by PgBouncer recovery conflicts.
- **Multi-domain**: Enumerate multiple domains in a single run with global deduplication.
- **Clean output**: Results to stdout, progress to stderr — pipeable into other tools without noise.

## How It Works

Most crt.sh tools hit the JSON HTTP endpoint, which is rate-limited, paginated, and slow for large domains. This tool connects directly to crt.sh's public PostgreSQL read replica (`crt.sh:5432`, user `guest`, database `certwatch`), the same database powering the website.

**Name sources** — for each certificate matching your target domain, five sources are extracted:

| # | Source | Field |
|---|---|---|
| 1 | Common Name + dNSName SANs | `2.5.4.3`, `san:dNSName` |
| 2 | Email SANs | `san:rfc822Name` (domain extracted after `@`) |
| 3 | URI SANs | `san:uniformResourceIdentifier` (hostname from URI) |
| 4 | CRL Distribution Point URLs | hostname extracted via regex |
| 5 | Authority Information Access URLs | hostname extracted via regex |

**Query strategy** — Phase 1 fetches all matching certificate IDs in a single query using the GIN index on `identities(certificate)` with `to_tsquery`. Phase 2 extracts all 5 name sources for each batch of 500 certificate IDs. New unique names are written to output immediately after each batch, so results stream progressively.

**Reliability** — crt.sh runs [PgBouncer](https://www.pgbouncer.org/) in statement pooling mode on a PostgreSQL hot-standby. Recovery conflicts can drop the TCP connection mid-query. The tool automatically reconnects and retries up to 5 times (with a 10-second delay) before giving up.

---

## Installation

**Requires Python 3.8+**

```bash
git clone https://github.com/leovng/crt.sh.enum.git
cd crt.sh.enum
pip install -r requirements.txt
```

Or install the single dependency directly:

```bash
pip install psycopg2-binary
```

---

## Usage

```
usage: crt.sh.enum.py [-h] [-d FILE] [-v] [-o FILE] [domains ...]

positional arguments:
  domains               Domain(s) to enumerate

options:
  -d FILE, --domains FILE   File containing newline-separated domains
  -v, --verbose             Print connection and query progress messages
  -o FILE, --output FILE    Write results to FILE instead of stdout
```

### Examples

```bash
# Single domain
python crt.sh.enum.py example.com

# Multiple domains
python crt.sh.enum.py example.com another.com

# Domains from a file
python crt.sh.enum.py -d domains.txt

# Verbose output, save to file
python crt.sh.enum.py example.com -d domains.txt -v -o results.txt

# Pipe into sort for clean output
python crt.sh.enum.py example.com | sort -u | tee subdomains.txt
```

Exit code is `1` if no results are found, `0` otherwise.

---

## Support

| Requirement | Details |
|---|---|
| Python | 3.8+ |
| External service | crt.sh public PostgreSQL replica (`crt.sh:5432`) |
| macOS | ✅ |
| Linux | ✅ |
| Windows | ✅ |

Results are deduplicated globally across all domains in a single run. Wildcard prefixes (`*.`) are automatically stripped from both input and output. The tool does not perform DNS resolution or liveness checks — it only enumerates names present in certificate transparency logs.

## Formatting

### Input

Domains are supplied as positional arguments or via a plain text file (`-d`). One domain per line. Lines starting with `#` and blank lines are ignored.

```
# targets
example.com
another.com
```

### Output

Results are written to **stdout** (or a file with `-o`), one subdomain per line. Progress and status messages go to **stderr**, keeping stdout clean for piping.

```
dev.example.com
mail.example.com
www.example.com
```

---

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to check the [issues](https://github.com/leovng/crt.sh.enum/issues) page or submit a pull request.

## Attribution

If you use crt.sh.enum in a project or research, a mention or link back to this repository is appreciated.

- Author: Leopold von Niebelschuetz-Godlewski
- Repository: [https://github.com/leovng/crt.sh.enum](https://github.com/leovng/crt.sh.enum)
- License: MIT

---

## Legal & Ethics

crt.sh.enum is intended solely for authorized security testing and research activities. Any unauthorized use is strictly prohibited. The author assumes no responsibility for misuse or damage resulting from improper or unlawful use.

---

## License

MIT License

Copyright (c) 2026 Leopold von Niebelschuetz-Godlewski

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
