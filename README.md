.....# HIPAA Gap Analyzer

**Summit Range Consulting** — HIPAA Security Rule (45 CFR §164.308–316) compliance gap analysis tool.

## Features

- 🔍 **28 HIPAA Security Rule controls** across all 4 safeguard categories
- 🎯 **Risk-weighted compliance score** (Critical/High/Medium controls weighted differently)
- 🔴 **Critical gap highlighting** with priority remediation guidance
- 📊 **Real-time risk level indicator** (Critical / High / Medium / Low)
- 🔎 **Filter by status** — view only gaps, critical items, or unassessed controls
- 📋 **Professional PDF-ready report** with executive summary and priority remediation list
- 🌑 Dark theme, mobile responsive

## HIPAA Coverage

| Safeguard | Controls | Weight |
|-----------|----------|--------|
| Administrative (§164.308) | 13 | 40% |
| Physical (§164.310) | 4 | 20% |
| Technical (§164.312) | 9 | 30% |
| Organizational (§164.314) | 2 | 10% |

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

## Usage

1. Work through each control — set **Compliant / Partial / Gap**
2. Add evidence notes in the text field
3. Use **filters** to focus on gaps or critical items
4. Export a full **Gap Analysis Report** (print-ready)

## Risk Scoring

Controls are weighted by risk level:
- 🔴 Critical: 4x weight
- 🟠 High: 3x weight  
- 🟡 Medium: 2x weight
- 🟢 Low: 1x weight

---

*Built by Summit Range Consulting | WOSB Certified*
