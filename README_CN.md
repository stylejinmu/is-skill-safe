# Is Skill Safe

[English](README.md) | 简体中文

一个专为 AI 智能体设计的安全审查 Skill，用于分析和评估其他 Skill 的安全性。

## 概述

当 AI 智能体使用第三方的 Skill 时，存在执行恶意或破坏性代码的潜在风险。`is-skill-safe` 提供了一个静态分析工具和评估工作流，帮助智能体在使用前自动审查目标 Skill 的 `SKILL.md` 文件及其关联脚本。

它会扫描常见的风险模式，例如：
- 破坏性的 Shell 命令（如 `rm -rf`、`sudo`、`chmod 777`）
- 潜在危险的 Python 操作（如 `os.system`、`eval`、`exec`、`subprocess`）
- 不安全的文件写入操作和 HTTP 请求

## 使用方法

此 Skill 旨在由 AI 智能体使用。智能体会对目标 Skill 目录执行内置的 `audit_skill.py` 脚本，并将发现的问题综合成一份安全报告。

### 手动执行

你也可以手动运行审查脚本：

```bash
python scripts/audit_skill.py <目标_skill_目录路径>
```

### 示例输出

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

## 目录结构

- `SKILL.md`: 指导 AI 智能体如何使用此审查 Skill 的核心说明文件。
- `scripts/audit_skill.py`: 执行静态分析的 Python 脚本。

## 局限性

此工具依赖于基于正则表达式的静态分析。它可能会产生误报（将安全代码标记为风险）或漏报（遗漏经过混淆的恶意代码）。它的设计初衷是辅助审查过程，而不能完全替代结合上下文的理解和人工代码审查。
