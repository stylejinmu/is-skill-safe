# Is Skill Safe

[English](README.md) | 简体中文

一个专为 AI 智能体设计的安全审查 Skill，用于分析和评估其他 Skill 的安全性。

## 概述

当 AI 智能体使用第三方的 Skill 时，存在执行恶意或破坏性代码的潜在风险。`is-skill-safe` 提供了一个静态分析工具和评估工作流，帮助智能体在使用前自动审查目标 Skill 的 `SKILL.md` 文件及其关联脚本。

它会扫描 59 种常见的风险模式，涵盖多个类别：
- 破坏性的 Shell 命令（如 `rm -rf`、`sudo`、`chmod +s`）
- 代码执行注入（如 `eval`、`exec`、`__import__`）
- 系统命令执行（如 `os.system`、`subprocess`）
- 不安全的反序列化和 XML 解析
- 硬编码凭证和路径遍历风险

## 使用方法

此 Skill 旨在由 AI 智能体使用。智能体会对目标 Skill 目录执行内置的 `audit_skill.py` 脚本，并将发现的问题综合成一份安全报告。

### 手动执行

你也可以手动运行审查脚本：

```bash
python scripts/audit_skill.py <目标_skill_目录路径>
```

### 白名单放行机制（误报豁免）

如果脚本将安全的代码标记为风险，你可以使用三种机制来豁免这些发现。被豁免的条目会在摘要中计数，以保留审计痕迹。

1. **行内豁免**：在源代码特定行的末尾添加 `# nosec` 或 `# audit: ignore` 注释。
2. **Skill 级配置文件**：在目标 Skill 的根目录下创建一个 `.audit_ignore` 文件。每行添加一个正则表达式，用于全局忽略匹配该描述的发现（例如 `open\(`）。
3. **CLI 参数**：在运行脚本时传递 `--allow <pattern>` 参数，以临时豁免匹配的发现：
   ```bash
   python scripts/audit_skill.py ./target-skill --allow "random\.\*"
   ```

### 示例输出

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

## 目录结构

- `SKILL.md`: 指导 AI 智能体如何使用此审查 Skill 的核心说明文件。
- `scripts/audit_skill.py`: 执行静态分析的 Python 脚本。

## 局限性

此工具依赖于基于正则表达式的静态分析。它可能会产生误报（将安全代码标记为风险）或漏报（遗漏经过混淆的恶意代码）。它的设计初衷是辅助审查过程，而不能完全替代结合上下文的理解和人工代码审查。
