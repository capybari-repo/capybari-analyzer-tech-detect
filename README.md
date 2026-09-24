# capybari-analyzer-tech-detect

**Capybari Source Intelligence: Technology & Version Detector: what is this built from?**

Detects languages, runtimes, frameworks, libraries, ORMs, databases, queues, search engines, cloud SDKs, AI SDKs, payments, monitoring, build and test tooling, and their versions. It reads package manifests, lockfile-resolved dependencies (when the `dependencies` capability ran), config files, and Dockerfile/compose images.

It flags **end-of-life** runtimes and frameworks (Node.js, Python, Go, Ruby, PHP, .NET, Django, Flask, Rails, Laravel, Angular, AngularJS, Vue 2, jQuery 1/2, Express 3) using a bundled, dated lifecycle table, so the check works offline.

| | |
|---|---|
| Requires | `inventory` |
| Uses when available | `fingerprint`, `dependencies` |
| Provides | `technologies` evidence |
| Scores | Technology Currency |
| Network / AI | none / none |
| Rules | [`rules/technologies.yaml`](rules/technologies.yaml) (≈120 signatures), [`rules/eol.yaml`](rules/eol.yaml) |

Contributions to the rule files are welcome. Every EOL date must cite its source.

```bash
go run ./cmd/capybari-tech-detect ./path/to/project
```

## License

Apache-2.0
