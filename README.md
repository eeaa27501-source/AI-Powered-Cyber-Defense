# AI-Powered Cyber Defense (Educational Prototype)

## Purpose
Demonstrate how security-event logs can be reviewed and how simple rules can raise alerts for review.

## Files
- `cyber_defense.py` — analyzer
- `sample_logs.csv` — synthetic example events only
- `README.md` — setup, limitations, and project notes

## Run
Install Python 3.10 or newer from https://www.python.org/downloads/
Open a terminal in this folder and run:
`python cyber_defense.py`

## Important accuracy note
The current prototype is rule-based, not a trained AI model. To meet the AI theme honestly, use Gemini or Microsoft Copilot to explain the anonymized alerts, compare possible false positives, and suggest improvements. Record the prompt and verify its suggestions. Do not upload private logs, passwords, or personal data.

## Possible future improvements
1. Build a graphical dashboard.
2. Import CSV logs chosen by the user.
3. Add a reviewed, labeled dataset and evaluate precision/recall.
4. Add role-based access and audit logging.
5. Integrate an approved AI service only after teacher approval and privacy review.

## Safety and limitations
The data is synthetic and uses documentation-only IP ranges. This program does not connect to networks, scan systems, block users, or prove that an attack occurred. Alerts are only clues for human review.
