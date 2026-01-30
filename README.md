# GuardDuty Empirical Evaluation (Research Repository)

This repository contains infrastructure-as-code and an experimental testing framework used to evaluate selected Amazon GuardDuty detection behaviours in a controlled AWS environment.

## Contents

```
.
├── README.md
├── SETUP_AND_TESTING_GUIDE.md
├── terraform_code/               # Experimental AWS infrastructure (Terraform)
└── python_framework/             # Attack orchestration, GuardDuty monitoring, metrics
```

## Reproducibility

The end-to-end procedure (deployment, configuration, execution, evidence collection, and cleanup) is documented in `SETUP_AND_TESTING_GUIDE.md`.

## Data and outputs

Experimental outputs are produced as JSON logs/results and may include GuardDuty finding exports. Refer to the setup guide for the expected output locations and the evidence collection procedure.

## Notes

- This repository is intended to support an academic dissertation; documentation is written in a deliberately plain, technical style.
- Code files are maintained separately from dissertation narrative text and appendices.
