---
name: is-skill-safe
description: 审查某个 Skill，分析其 SKILL.md 文件和任何关联的脚本。解释它的作用，识别任何潜在的安全风险，并告诉我它是否可以安全使用。
---

# Is Skill Safe

This skill audits other skills by analyzing the `SKILL.md` file and any associated scripts to explain the skill's purpose, identify potential security risks, and provide a safety assessment.

## How to Use

### Step 1: Run the Audit Script

Use the `shell` tool to run `audit_skill.py` against the target skill directory:

```bash
python <path_to_this_skill>/scripts/audit_skill.py <path_to_target_skill>
```

### Step 2: Analyze the Output

The script outputs:
- The name and description parsed from the skill's YAML frontmatter.
- Any risky patterns found in `SKILL.md` (e.g., `rm -rf`, `sudo`, `eval`).
- Per-script findings with severity level (HIGH / MEDIUM / LOW) and line numbers.
- A summary of total findings and suppressed items.

### Step 3: Provide a Summary

Synthesize the findings into a clear report covering:

1. **Explanation of Purpose** — What does the skill do?
2. **Security Risks Identified** — List findings and explain *why* they are risky in context.
3. **Safety Assessment** — Is the skill safe to use? If risks exist, advise on mitigation.

---

## Allowlist (False Positive Suppression)

Some flagged patterns may be intentional and safe in context. Three suppression mechanisms are available:

### 1. Inline suppression (per-line)

Add a comment at the end of any line in the target skill's scripts:

```python
result = open("output.txt", "w")  # nosec
result = open("output.txt", "w")  # audit: ignore
```

### 2. `.audit_ignore` file (per-skill)

Place a `.audit_ignore` file in the **target skill's root directory**. Each non-empty, non-comment line is a regex pattern matched against finding descriptions. Matching findings are suppressed globally for that skill.

```
# .audit_ignore example
# Allow open() writes — skill only writes to its own output directory
open\(.*'w'

# Allow random module — used for non-security shuffle only
random\.\*
```

Then run the audit normally:

```bash
python <path_to_this_skill>/scripts/audit_skill.py <path_to_target_skill>
```

### 3. CLI `--allow` flag

Pass one or more `--allow <pattern>` arguments to suppress matching findings on the fly:

```bash
python <path_to_this_skill>/scripts/audit_skill.py <path_to_target_skill> \
  --allow "random\.\*" \
  --allow "open\("
```

Multiple `--allow` flags can be combined. Suppressed findings are counted and shown in the summary.

---

## Important Considerations

- **Static Analysis Limitations**: The script uses regex-based pattern matching. It may produce false positives (flagging safe code) or false negatives (missing obfuscated code).
- **Manual Review**: Always supplement script findings with your own code review. If `subprocess.run` is flagged, check *what* command it runs. If a file write is flagged, check *where* and *what* it writes.
- **Context Matters**: Operations like writing to a file or making an HTTP request can be perfectly normal. Evaluate risk in the context of the skill's stated purpose.
- **Allowlist Responsibility**: Suppressing a finding does not make the code safe — it means you have reviewed and accepted the risk. Document your reasoning in `.audit_ignore` comments.
