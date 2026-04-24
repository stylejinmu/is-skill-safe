# Is Skill Safe

A security auditing skill designed for AI agents to analyze and evaluate the safety of other skills.

## Overview

When AI agents use third-party skills, there is a potential risk of executing malicious or destructive code. `is-skill-safe` provides a static analysis tool and an evaluation workflow to help agents automatically review a skill's `SKILL.md` file and its associated scripts before using it.

It scans for common risky patterns such as:
- Destructive shell commands (e.g., `rm -rf`, `sudo`, `chmod 777`)
- Potentially dangerous Python operations (e.g., `os.system`, `eval`, `exec`, `subprocess`)
- Unsafe file write operations and HTTP requests

## Usage

This skill is intended to be used by an AI agent. The agent will execute the included `audit_skill.py` script against the target skill directory and synthesize the findings into a safety report.

### Manual Execution

You can also run the audit script manually:

```bash
python scripts/audit_skill.py <path_to_target_skill_directory>
```

### Example Output

```text
Auditing skill at: /path/to/example-skill

--- SKILL.md Analysis ---
Frontmatter found.
Name: example-skill
Description: An example skill.
No obvious risky patterns found in SKILL.md.

--- Scripts Analysis ---

Analyzing script: scripts/run.py
Potential Risks:
- subprocess.run call
- File write operation

--- Summary ---
Please review the findings above to determine if the skill is safe to use.
Note: This is a static analysis tool and may not catch all potential security issues.
Always manually review complex or obfuscated code.
```

## Structure

- `SKILL.md`: The core instructions for the AI agent on how to use this auditing skill.
- `scripts/audit_skill.py`: The Python script that performs the static analysis.

## Limitations

This tool relies on static analysis using regular expressions. It may produce false positives (flagging safe code) or false negatives (missing obfuscated malicious code). It is designed to assist in the review process, not to replace contextual understanding and manual review.
