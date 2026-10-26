# FrogHacker Antihallucination 🧠

<div align="center">

**算法抗幻觉（开源版）** — 四层确定性验证 · FactGate 事实断言裁决

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](./pyproject.toml)
[![零依赖](https://img.shields.io/badge/依赖-纯标准库-important.svg)]()

响应时代号召，开源蛙客网络安全分析自动化平台的**算法抗幻觉模块**。

</div>

## 这是什么

蛙客（FrogHacker）的安全分析输出**不靠 LLM 可靠性，靠确定性算法验证**。本仓库开源其中的抗幻觉核心：

> **LLM 输出里以事实身份呈现的断言 ⊆ 已验证断言集** —— 这是结构保证，不是概率保证。

| 组件 | 作用 |
|------|------|
| 四层体系（`__init__.py`） | ①生成式约束 ②判别式代数 ③信息守恒 ④双向乘积衰减，逐层收缩系统错误概率 |
| FactGate（`fact_gate.py`） | 第⑤层：LLM 输出拆原子断言 → 绑外部证据 → 确定性裁决 → 分级门控 |

核心公式：

```
P(系统输出错误) ≤ min(生成式不完备, 判别式遗漏, 信息守恒误判, 双向汇合假匹配)
```

## ✨ 特性

- **四层确定性验证** — 结构化模板 / 纯算法判别 / 信息守恒安全阀 / 乘积衰减，全部无 LLM 参与
- **FactGate 断言裁决** — 输出拆成原子断言，逐条裁决 `verified / contradicted / unverifiable`
- **分级门控** — fact/observation 无证据即删除，conclusion 降级标注「未验证假设」，action 保留标注
- **可插拔证据源** — 内置 3 个纯标准库 provider，`register_provider()` 接入自己的数据源
- **零依赖** — 纯 Python 标准库（re / hashlib / math / dataclasses）

## 🚀 快速上手

### 四层抗幻觉

```python
from antihallucination import HallucinationGuard

guard = HallucinationGuard()
verdict = guard.evaluate(
    output="flag{abc}",
    inputs={"pattern": "flag"},
    expected_type="flag",
    operation="grep",
)
print(verdict.risk_level.value)   # safe / low / medium / high / critical
print(verdict.reason)             # 哪一层触发警告
```

### FactGate 事实断言裁决

```python
from antihallucination import FactGate

fg = FactGate(domain="web")
report = fg.gate(
    "Apache 2.4.49 存在路径穿越漏洞。",
    context={"report_text": "Apache 2.4.49 存在路径穿越漏洞。"}  # 工具实测输出
)
for v in report.claims:
    print(v.claim.subject, "→", v.status)   # verified / contradicted / unverifiable
print(report.filtered_output)               # 门控后的干净输出
```

### 自定义证据源

```python
from antihallucination import register_provider, Evidence

def my_kb_provider(claim, context):
    # 接入你自己的知识库 / CVE 数据库 / 任意数据源
    if claim.subject in my_db:
        return Evidence("kb_entry", my_db[claim.subject], "my_kb", True)
    return None

register_provider("kb_entry", my_kb_provider)
```

## 🏗️ 架构

```
LLM 输出文本
  → ClaimExtractor  拆原子断言 + 分类（fact/observation/conclusion/action）
  → EvidenceBinder  按类型路由 provider 取外部证据（tool_stdout/file_content/math_verify/自定义）
  → FactVerifier    确定性裁决（硬匹配，不经过 LLM）
  → Gate            分级门控 → 干净输出 + GateReport
```

## 📁 目录结构

```
froghacker-antihallucination/
├── LICENSE               Apache-2.0
├── NOTICE                专利保留声明
├── MANIFEST.md           文件清单与剥离说明
├── pyproject.toml        打包配置
└── antihallucination/
    ├── __init__.py       四层抗幻觉体系
    └── fact_gate.py      FactGate 事实断言裁决
```

## 🛡️ 专利保护与开源边界

本仓库**不引用任何数学引擎**，与专利04「知识库结构自检」零交集。为明确起见，专利保留声明见 [NOTICE](./NOTICE)。

## 📄 许可证

Apache License 2.0，© 2026 FrogHacker (wwyhji)。专利保留声明见 [NOTICE](./NOTICE)。
