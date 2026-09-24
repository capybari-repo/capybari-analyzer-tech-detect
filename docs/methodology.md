# Methodology: Technology & Version Detector

## Detection

A technology is detected when any signature in `rules/technologies.yaml` matches:

- **package names** per ecosystem (npm, PyPI, Go, Maven, NuGet, Packagist, RubyGems, Cargo), from manifests and, when available, the resolved dependency list
- **files** (e.g. `angular.json`, `tailwind.config.js`, `wp-config.php`, `*.tf`)
- **container images** from Dockerfile `FROM` and compose/Kubernetes `image:` lines (e.g. `postgres`, `redis`)

Languages with ≥ 5 % of source lines (or ≥ 500 lines) and the runtimes from the fingerprint are added. Versions prefer exact pins over ranges.

## End-of-life

`capybari-core/lifecycle/eol.yaml` (shared with the website capabilities) holds release-line end dates from https://endoflife.date and vendor pages, stamped `as_of`. A detected version maps to its release line (major.minor for Python, Go and Django; major for Node.js and Angular; target framework for .NET). If the line's date is in the past, or it is marked `unsupported`, a finding is raised:

| Product kind | Severity |
|---|---|
| runtime (Node.js, Python, Go, Ruby, PHP, .NET) | high |
| framework (Django, Flask, Rails, Laravel, Angular, AngularJS, Vue, Express) | medium |
| library (jQuery) | low |

Confidence is **high** for an exact version, **medium** for a range such as `>=12`.

The bundled table can go stale. Each finding links to its source, and the report states the table date as a limitation.

## Contributes to

**Technology Currency** (dimension `evolution`).
