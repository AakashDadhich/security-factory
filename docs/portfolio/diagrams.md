# Diagrams

Four views of the factory. Sources: [pipeline.md](../pipeline.md), [adapter.md](../adapter.md), [.github/workflows/factory.yml](../../.github/workflows/factory.yml).

## End-to-end flow

An issue or a push starts a run. The gate decides. A failed gate in spec, change or fix mode starts the fix loop (at most two rounds). A merged change feeds the improvement loop: the next change run reads the committed plan and threat model and only re-analyses what it touches.

```mermaid
flowchart TD
    issue([Issue labelled factory:spec or factory:change]) --> auth{authorize<br/>actor and author<br/>on allowlist}
    push([Push or pull request]) --> scan
    auth -->|no| refused([Run refused, no model called])
    auth -->|yes| plan[plan<br/>ASVS level, abuse cases]
    plan --> tm[threat model<br/>pytm, STRIDE, LINDDUN, attack trees]
    tm --> gen[generate code<br/>read-only AI, patch policy]
    gen --> commit[commit to factory/issue<br/>bot, never default branch]
    commit --> rev[second-agent review]
    rev --> scan[scanners in parallel]
    scan --> gate{gate<br/>fail closed}
    gate -->|pass| record[(factory-record branch<br/>history, SBOM, findings)]
    gate -->|pass| merge([Owner reviews and merges])
    gate -->|fail, iteration below 2| fix[factory-fix dispatch]
    fix --> gen
    gate -->|fail, iteration 2| human([Comment and factory:needs-human])
    merge --> sec[(security/ plan and threat model<br/>in the repo)]
    sec -.->|next change run reads it| plan
    record -.->|recent failures and findings| plan
```

## CI layout

The project holds only a stub. Everything else lives in the factory repository and is checked out into `.factory/` at the pinned ref.

```mermaid
flowchart LR
    subgraph project[Project repository]
        stub[.github/workflows/factory.yml<br/>stub, calls factory at v1]
        cfg[.factory.yml]
        sec[security/]
    end
    subgraph factory[security-factory repository]
        wf[reusable workflow<br/>on: workflow_call]
        act[composite actions<br/>setup-factory]
        py[factory/ Python modules<br/>python -m factory.stage]
        lock[tools/versions.lock<br/>version, URL, SHA-256 or digest]
        pr[prompts, rules, schemas]
    end
    subgraph tools[Pinned tools on the runner]
        t1[Gitleaks, Semgrep, CodeQL]
        t2[OSV-Scanner, Syft, Grype]
        t3[ZAP, MobSF in containers]
        t4[Xcode, SwiftLint, claude-code]
    end
    stub -->|workflow_call, secrets inherit| wf
    cfg --> wf
    wf --> act
    act --> py
    py -->|install, checksum verified| lock
    lock --> tools
    py --> pr
    py -->|findings.json per stage| gate[gate]
    sec --> py
```

## Model adapter

Stages never call a model directly. They hand the adapter a prompt, inputs and a schema, and get validated JSON back.

```mermaid
flowchart LR
    s1[plan] --> ad
    s2[threat model] --> ad
    s3[codegen and fix] --> ad
    s4[review] --> ad
    ad[factory.adapter<br/>prompt, inputs, schema, allowed tools]
    ad -->|FACTORY_MODEL_ADAPTER=claude_code| cc[Claude Code CLI<br/>restricted, no Bash, no web]
    ad -->|FACTORY_MODEL_ADAPTER=fake| fk[canned replies for tests]
    ad -.->|one more adapter file| other[another model, later]
    cc --> model[(Claude model)]
    ad --> out[reply.json plus meta.json<br/>validated against the schema]
    ad -->|exit 75| lim([usage limit, stage fails])
```

## Job graphs by mode

Every job also needs `authorize` through `setup`. The scanners are `secrets`, `sast-semgrep`, `sast-codeql`, `sast-eslint`, `deps-sbom` and `dast-web` for web, and `apple-build` with `apple-checks`, `sast-swiftlint`, `sast-codeql-swift`, `deps-sbom` and `mobsf` for Apple.

Spec and change:

```mermaid
flowchart LR
    authorize --> setup --> plan --> threat-model --> codegen-ai --> codegen-commit --> review --> scanners
    plan --> plan-comment
    scanners --> gate --> next-step
    gate --> record
```

Fix:

```mermaid
flowchart LR
    authorize --> setup --> fix-input --> codegen-ai --> codegen-commit --> review --> scanners
    scanners --> gate --> next-step
    gate --> record
    next-step -.->|gate failed, iteration below 2| dispatch([factory-fix, iteration + 1])
    next-step -.->|iteration 2| needs-human([comment and factory:needs-human])
```

Check:

```mermaid
flowchart LR
    authorize --> setup --> ai-eligible
    setup --> scanners
    ai-eligible -->|run_ai| threat-model
    ai-eligible -->|run_ai| review
    review --> scanners
    threat-model --> gate
    scanners --> gate --> record
```
