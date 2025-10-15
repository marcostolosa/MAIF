
# MITRE ATT&CK Intelligence Framework

Advanced CLI tool for querying and analyzing MITRE ATT&CK techniques. Built for threat hunters, red teamers, and security researchers who need fast, filterable access to ATT&CK data.

## Overview

This tool fetches the MITRE ATT&CK Enterprise framework, parses techniques with full metadata, applies sophisticated filtering, and exports results in multiple formats. Includes local caching, async I/O, and a risk scoring system based on operational factors.

## Requirements

- Python 3.9+
- Internet connection (first run only)

```bash
pip install httpx rich typer pydantic diskcache
```

## Installation

```bash
git clone https://github.com/marcostolosa/MAIF.git
cd MAIF
pip install -r requirements.txt
```

## Usage

### Basic Search

```bash
# Search by keyword
./app.py search -k "credential"

# Search with tactic filter
./app.py search -k "dump" -t credential-access

# Multiple tactics
./app.py search -t persistence -t privilege-escalation
```

### Advanced Filtering

```bash
# Platform-specific techniques
./app.py search -p Windows -p Linux

# Risk level filtering
./app.py search --min-risk HIGH

# Include deprecated techniques
./app.py search -k "lateral" --include-deprecated

# Combine filters
./app.py search -k "bypass" -t defense-evasion -p Windows --min-risk CRITICAL
```

### Export Options

```bash
# CSV export
./app.py search -k "process" --export-csv results.csv

# JSON export
./app.py search -t execution --export-json techniques.json

# Markdown report
./app.py search --min-risk HIGH --export-md report.md

# Multiple exports
./app.py search -k "token" --export-csv data.csv --export-json data.json --export-md report.md
```

### Statistics

```bash
# Show distribution stats
./app.py search --stats

# Stats for specific query
./app.py search -t initial-access --stats
```

### Utility Commands

```bash
# List all available tactics
./app.py list-tactics

# Clear cached data
./app.py clear-cache

# Verbose output
./app.py search -k "shell" -v
```

## Command Reference

### search

Primary command for querying techniques.

**Options:**

|Flag                  |Description                        |Example                 |
|----------------------|-----------------------------------|------------------------|
|`-k, --keyword`       |Search term (name, description, ID)|`-k "credential"`       |
|`-t, --tactic`        |Filter by tactic (repeatable)      |`-t persistence`        |
|`-p, --platform`      |Filter by platform (repeatable)    |`-p Windows`            |
|`-r, --min-risk`      |Minimum risk level                 |`--min-risk HIGH`       |
|`-l, --limit`         |Display limit (default: 50)        |`-l 100`                |
|`--include-deprecated`|Include deprecated techniques      |                        |
|`--include-revoked`   |Include revoked techniques         |                        |
|`--export-csv`        |Export to CSV                      |`--export-csv out.csv`  |
|`--export-json`       |Export to JSON                     |`--export-json out.json`|
|`--export-md`         |Export to Markdown                 |`--export-md report.md` |
|`-s, --stats`         |Show statistics instead of table   |                        |
|`-v, --verbose`       |Enable debug logging               |                        |

### list-tactics

Displays all MITRE ATT&CK tactic phases.

### clear-cache

Removes all cached ATT&CK data. Next search will re-fetch from GitHub.

## Risk Scoring

Techniques are scored based on operational factors:

**Scoring Criteria:**

- Multi-platform support (broader attack surface)
- Low permission requirements (easier exploitation)
- Defense bypass capabilities (evasion potential)
- Subtechnique complexity
- Deprecation status (negative weight)

**Risk Levels:**

- `CRITICAL`: Score 7+ (high impact, low barrier)
- `HIGH`: Score 5-6
- `MEDIUM`: Score 3-4
- `LOW`: Score 0-2
- `INFO`: Deprecated/revoked techniques

This is not CVSS. It’s a heuristic for threat prioritization.

## Architecture

```
app.py
├── Models (Technique, ExternalReference, Enums)
├── CacheManager (diskcache with TTL)
├── MitreAttackFetcher (async httpx with retry)
├── TechniqueParser (JSON to dataclass, filtering)
├── ExportHandler (CSV, JSON, Markdown)
├── DisplayHandler (Rich tables and stats)
└── MitreAttackIntelligence (orchestrator)
```

## Cache Behavior

- Default location: `~/.mitre_attack/`
- TTL: 24 hours
- Storage: diskcache (SQLite-backed)
- Invalidation: Manual via `clear-cache` command

First run downloads ~8MB JSON from GitHub. Subsequent queries use cache unless expired.

## Output Formats

### CSV

Columns: `MITRE_ID`, `Name`, `Tactics`, `Platforms`, `Risk_Level`, `Risk_Score`, `Permissions`, `Defense_Bypassed`, `Detection`, `Description`, `URL`

### JSON

Structured array with full technique metadata including risk scores.

### Markdown

Formatted report with sections per technique, detection guidance, and references.

## Filtering Logic

All filters use AND logic:

```bash
# Returns techniques matching ALL conditions:
# - Contains "token" in name/description
# - Used in credential-access OR privilege-escalation
# - Targets Windows
# - Risk level HIGH or above
./app.py search -k "token" -t credential-access -t privilege-escalation -p Windows --min-risk HIGH
```

## Performance

- Initial load: 2-5 seconds (network dependent)
- Cached queries: <100ms
- Async HTTP with connection pooling
- In-memory filtering after load

## Error Handling

- HTTP failures: 3 retries with exponential backoff
- Cache errors: Graceful fallback to network fetch
- Invalid filters: Early validation with clear messages
- Network timeout: 30 seconds default

## Development

### Project Structure

```
.
├── app.py              # Main application
├── requirements.txt    # Dependencies
└── README.md           # This file
```

### Adding Features

Key extension points:

- `Technique.calculate_risk_score()` - Modify scoring logic
- `TechniqueParser.filter_techniques()` - Add filter types
- `ExportHandler` - Add export formats
- `TacticPhase` enum - Update if MITRE adds tactics

### Testing Locally

```bash
# Verbose mode for debugging
./app.py search -k "test" -v

# Force cache refresh
./app.py clear-cache
./app.py search -k "test"

# Validate exports
./app.py search -k "cred" --export-json test.json
jq '.[] | .mitre_id' test.json
```

## Known Limitations

- Enterprise ATT&CK only (no Mobile/ICS)
- No STIX parsing (uses raw JSON)
- Risk scores are heuristic, not authoritative
- Cache invalidation is manual
- No relationship mapping (technique -> software -> groups)

## Data Source

All data fetched from official MITRE CTI repository:

```
https://github.com/mitre/cti/
```

Uses `enterprise-attack.json` from master branch.

## License

MIT

## Author

Marcos Tolosa - Independent security researcher

## References

- MITRE ATT&CK: <https://attack.mitre.org>
- ATT&CK Navigator: <https://mitre-attack.github.io/attack-navigator/>
- STIX 2.0: <https://oasis-open.github.io/cti-documentation/>

-----

Built for practitioners who need data, not dashboards.
