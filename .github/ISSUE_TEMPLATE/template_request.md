---
name: Template Suggestion
about: Propose a new scan template for common BOLA/IDOR patterns
title: '[TEMPLATE] '
labels: template, enhancement
assignees: jojin1709
---

**Endpoint Pattern**
- Path: `/api/.../{id}`
- HTTP Method: [GET / POST / PUT / DELETE]
- Typical Severity: [Critical / High / Medium / Low]

**Description**
Explain what resource this template targets and why it is prone to BOLA / IDOR.

**Example YAML**
```yaml
id: idor-...
name: ...
path: ...
```
