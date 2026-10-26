# antihallucination-oss 文件清单与剥离说明

> 生成日期：2026-10-26
> 来源仓库：`D:\froghacker`（蛙客 v5.2，主仓库为专有软件）

## 一、开源内容（本仓库）

| 文件 | 能力 | 来源 |
|------|------|------|
| `antihallucination/__init__.py` | 四层抗幻觉体系（生成式约束 / 判别式代数 / 信息守恒 / 双向乘积衰减） | `tools/antihallucination/__init__.py` |
| `antihallucination/fact_gate.py` | 第⑤层 FactGate（原子断言提取 → 证据绑定 → 确定性裁决 → 分级门控） | `tools/antihallucination/fact_gate.py` |

## 二、剥离内容（**不在**本仓库，平台耦合）

| 位置 | 剥离内容 | 原因 |
|------|---------|------|
| `fact_gate.py` `_provider_kb` | KB 知识库证据源（`tools.kb.store`） | 平台 KB 存储依赖 |
| `fact_gate.py` `_provider_cve` | CVE 数据库证据源（`tools.vuln_dispatch`） | 平台漏洞调度依赖 |
| `fact_gate.py` 4 处 | `tools.swallow_trap` | 平台错误记录 → 标准库 `logging` |
| `__init__.py` 末尾 | `tools.core.cli_registry` CLI 注册入口 | 平台 CLI 架构 |

## 三、改写说明

1. 删除 `_provider_kb` + `_provider_cve`（两个平台特定证据源）。
2. `default_providers` 保留 3 个纯标准库 provider：`tool_stdout`（工具输出）/ `file_content`（文件内容）/ `math_verify`（注入的确定性结果）。
3. `_ROUTING` 里 cve/version 缺 provider 时 `EvidenceBinder.bind` 自动跳过（`if not fn: continue`），不报错。
4. 用户可用 `register_provider("kb_entry", my_fn)` 接入自己的数据源——剥离不损失扩展性。
5. 4 处 `swallow_trap` → `logging`；删除 CLI 注册入口，保留 `if __name__ == "__main__"`。

## 四、与专利04 的关系

本仓库**不引用任何数学引擎**（`_provider_math` 是读取 context 注入的已算结果，非 import 数学引擎），与专利04 零交集。专利保留声明见 NOTICE。
