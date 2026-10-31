# Contributing to IDORaider

Thank you for your interest in contributing to **IDORaider**! We welcome contributions from ethical hackers, security researchers, and developers.

## Ways to Contribute

1. **Submit New Scan Templates**: Help expand the community template set in `templates/` with common IDOR/BOLA endpoint patterns.
2. **Report Bugs**: Open an issue describing the unexpected behavior, steps to reproduce, and target environment details.
3. **Suggest Features**: Propose new capabilities, protocol improvements, or output formats.
4. **Code Improvements**: Submit pull requests for engine optimizations, documentation, or new features.

---

## Contributing Templates

Templates live in `templates/*.yaml`. When creating a new template:
- Ensure the filename describes the vulnerability (e.g. `idor-invoice-download.yaml`).
- Keep matching words specific enough to avoid high false-positive rates on common 200 OK error responses.
- Follow the standard template structure:

```yaml
id: idor-example
name: Example Endpoint IDOR
severity: high # critical | high | medium | low | info
description: Resource accessible with modified ID
method: GET
path: /api/v1/resources/{id}
headers:
  Authorization: Bearer {token}
ids:
  - 1
  - 2
match_status:
  - 200
match_words:
  - sensitive_field
```

---

## Development Guidelines

### Zero External Dependencies Rule
A core architectural tenet of IDORaider is **zero external dependencies**. All code must use only the Go standard library so users can build and run offline without supply-chain risk.

### Testing
Always ensure existing and new tests pass before opening a Pull Request:

```bash
# Run all tests
go test -v ./...

# Build the binary
go build -o idoraider ./cmd/idoraider
```

### Pull Request Process
1. Fork the repository and create your branch from `main`.
2. Write clean, readable Go code following standard conventions (`gofmt`).
3. Add unit tests for any new engine or parsing logic.
4. Update the `README.md` if your change adds or changes CLI flags or templates.
5. Open a Pull Request with a clear description of the problem solved.

---

## Code of Conduct

Please review and adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).
