# Is Skill Safe

English | [简体中文](README_CN.md)

A security auditing skill designed for AI agents to analyze and evaluate the safety of other skills.

## Overview

When AI agents use third-party skills, there is a potential risk of executing malicious or destructive code. `is-skill-safe` provides a static analysis tool and an evaluation workflow to help agents automatically review a skill's `SKILL.md` file and its associated scripts before using it.

It scans for 59 common risky patterns across multiple categories:
- Destructive shell commands (e.g., `rm -rf`, `sudo`, `chmod +s`)
- Code execution injection (e.g., `eval`, `exec`, `__import__`)
- System command execution (e.g., `os.system`, `subprocess`)
- Unsafe deserialization and XML parsing
- Hardcoded credentials and path traversal risks

## Usage

This skill is intended to be used by an AI agent. The agent will execute the included `audit_skill.py` script against the target skill directory and synthesize the findings into a safety report.

### Manual Execution

You can also run the audit script manually:

```bash
python scripts/audit_skill.py <path_to_target_skill_directory>
```

### Allowlist (False Positive Suppression)

If the script flags safe code as risky, you can suppress these findings using three mechanisms. Suppressed findings are counted in the summary to maintain an audit trail.

1. **Inline Suppression**: Append `# nosec` or `# audit: ignore` to the end of the specific line in the source code.
2. **Per-Skill File**: Create a `.audit_ignore` file in the target skill's root directory. Add regex patterns (one per line) matching the finding descriptions you want to ignore globally for that skill (e.g., `open\(`).
3. **CLI Flag**: Pass `--allow <pattern>` when running the script to suppress findings on the fly:
   ```bash
   python scripts/audit_skill.py ./target-skill --allow "random\.\*"
   ```

### Example Output

```text
Auditing skill at: /path/to/example-skill

============================================================
SKILL.md
============================================================
  Name       : example-skill
  Description: An example skill.
  No risky patterns found in SKILL.md.

============================================================
Script: scripts/run.py
============================================================
  Found 2 potential risk(s):
  [HIGH] Line 12: subprocess.run() - runs subprocess (risky if shell=True)
         > subprocess.run(cmd, shell=True)
  [MEDIUM] Line 45: open(..., 'w'/'a') - writes or appends to file
         > with open("output.txt", "w") as f:

============================================================
SUMMARY
============================================================
  Total findings   : 2
  HIGH             : 1
  MEDIUM           : 1
  LOW              : 0
  Suppressed       : 1  (via allowlist / inline markers)

  HIGH severity findings require careful manual review before use.
```

## Structure

- `SKILL.md`: The core instructions for the AI agent on how to use this auditing skill.
- `scripts/audit_skill.py`: The Python script that performs the static analysis.

## Limitations

This tool relies on static analysis using regular expressions. It may produce false positives (flagging safe code) or false negatives (missing obfuscated malicious code). It is designed to assist in the review process, not to replace contextual understanding and manual review.
