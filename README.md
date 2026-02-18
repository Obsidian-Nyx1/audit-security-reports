# Security Report Audit Agent

Profile-aware audit agent for offensive and purple-team report QA.

## Primary flow
Run:
```bash
./audit_agent.py
```

Then:
1. MSF-style title + rotating joke appears.
2. Usage help appears.
3. You select a report type (`press number 1-10`).
4. You provide report file/path.
5. You choose `doc` or `pdf` output.

## Quick direct usage
```bash
./audit_agent.py "example.doc" --output-format pdf --profile pentest_general
./audit_agent.py "example.pdf" --output-format doc --profile web_pentest
./audit_agent.py "/full/path/to/example.xml" --output-format pdf --profile purple_team
```

## Available profiles
1. `pentest_general`
2. `web_pentest`
3. `internal_pentest`
4. `external_pentest`
5. `red_team`
6. `purple_team`
7. `adversary_emulation`
8. `phishing_assessment`
9. `wireless_assessment`
10. `ad_assessment`

List profiles:
```bash
./audit_agent.py --list-profiles
```

## Outputs
- `output/control_assessment.json`
- `output/control_assessment.md`
- `output/<name>.doc` or `output/<name>.pdf`

## Supported input types
- `.txt`, `.md`, `.log`, `.json`, `.csv`, `.xml`, `.doc`, `.docx`, `.pdf`
