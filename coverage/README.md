# MITRE ATLAS coverage map (draft)

`atlas-coverage.csv` triages every technique in MITRE ATLAS release 2026.09 (208 techniques: 120 techniques and 88 sub-techniques across 16 tactics) by where Guardian Protocol can act on it.

| Category | Techniques | What it means |
| --- | --- | --- |
| Agent runtime | 63 | Happens while an agent runs: prompt injection, tool poisoning, exfiltration through tool calls, context poisoning, agent-to-agent communication. The scan can test these and the sensor can detect most of them. |
| General security with an AI angle | 60 | Classic attacks (accounts, phishing, public-facing apps) aimed at AI systems. Partly visible to the sensor; existing security tools cover the rest. |
| Attacker preparation | 46 | Reconnaissance and resource development before contact. Not visible at runtime. |
| Model and training pipeline | 31 | Training-data poisoning, backdoors, adversarial examples, model extraction. For model owners and labs, not the gateway sensor. |
| Supply chain | 8 | Compromised dependencies, datasets and hardware. Partly testable. |

Every row is marked `draft triage`: the categories were assigned by a first pass and need human review. Reviewing a row and writing its pattern (test plus detection) is a good first contribution.

Source: [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data), release 2026.09. MITRE ATLAS is a trademark of The MITRE Corporation.
