# security/

This folder is written by the Security Software Factory and committed with your code. Read it, review changes to it in pull requests, and don't edit the generated files by hand.

| File | What it is |
|---|---|
| `plan.json` | The living plan: features, security requirements and abuse cases for the project |
| `threats.json` | The threat model (STRIDE, plus LINDDUN and attack trees when they apply) with a mitigation for each threat |
| `tm.py` | The pytm model of the system that the threat model is built from |

The files appear after the first `factory:spec` issue is processed and are updated by `factory:change` issues. A scan history and the latest SBOM live on the `factory-record` branch, not here.
