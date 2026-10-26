"""算法抗幻觉模块 — 四层体系确保系统正确性而非依赖 LLM 可靠性。

① 生成式约束 — 结构化模板缩小 LLM 输出空间（可判定化）
② 判别式代数 — 纯算法验证 (inputs, output) → bool
③ 信息守恒 — 产物信息量 ≤ 源信息量 (化学反应安全阀)
④ 双向乘积衰减 — P(假汇合) = P(A 幻觉) × P(B 兼容幻觉)

核心公式:
    P(系统输出错误) ≤ min(
        P(生成式维度不完备),        # 第①层
        P(判别式遗漏),              # 第②层
        P(信息守恒误判),            # 第③层
        P(双向汇合假匹配)            # 第④层
    )

用法:
    from antihallucination import (
        HallucinationGuard, GuardConfig, GuardVerdict,
        SignatureCompressor, EntropyMeter,
    )

    guard = HallucinationGuard()
    verdict = guard.evaluate(output="flag{abc}", inputs={"pattern": "flag"},
                              expected_type="flag", operation="grep")
    print(verdict.risk_level, verdict.reason)
"""

from __future__ import annotations

import enum
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .fact_gate import (  # 第⑤层：事实断言裁决
    Claim, ClaimExtractor, ClaimVerdict, Evidence, EvidenceBinder,
    FactGate, FactVerifier, GateReport, default_providers, register_provider,
)


# ── Risk Level ──────────────────────────────────────────────────────

class RiskLevel(enum.Enum):
    """幻觉风险等级。"""
    SAFE = "safe"               # 通过所有层，低风险
    LOW = "low"                 # 1层警告
    MEDIUM = "medium"           # 2层警告
    HIGH = "high"               # 1层失败
    CRITICAL = "critical"       # 多层失败

    @property
    def is_acceptable(self) -> bool:
        return self in (RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM)


# ── Layer Results ───────────────────────────────────────────────────

@dataclass
class LayerResult:
    """单层验证结果。"""
    passed: bool = False
    risk: float = 0.0            # 0.0 (安全) ~ 1.0 (幻觉)
    detail: str = ""
    layer: int = 0

    def to_dict(self) -> dict:
        return {"layer": self.layer, "passed": self.passed,
                "risk": self.risk, "detail": self.detail[:200]}


# ── Guard Verdict ───────────────────────────────────────────────────

@dataclass
class GuardVerdict:
    """抗幻觉验证最终结果。"""
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_score: float = 0.0       # 0.0 ~ 1.0
    reason: str = ""
    layers: List[LayerResult] = field(default_factory=list)
    confidence: float = 1.0       # 推荐置信度 (1 - risk)

    def to_dict(self) -> dict:
        return {
            "risk_level": self.risk_level.value,
            "risk_score": round(self.risk_score, 3),
            "confidence": round(self.confidence, 3),
            "reason": self.reason,
            "layers": [l.to_dict() for l in self.layers],
        }


# ── Signature Compressor ────────────────────────────────────────────

@dataclass
class Signature:
    """元组签名 — 有限维投影。

    签名不是事物本身，而是对真实世界的有限维可判定投影。
    签名维度越完备，验证越可靠。
    """
    type_name: str = ""
    value_hash: str = ""
    input_hash: str = ""
    template_hash: str = ""
    entropy: float = 0.0
    token_count: int = 0

    def to_dict(self) -> dict:
        return {
            "type": self.type_name,
            "value_hash": self.value_hash[:8],
            "input_hash": self.input_hash[:8],
            "entropy": round(self.entropy, 3),
            "tokens": self.token_count,
        }


class SignatureCompressor:
    """签名压缩器 — 将任意值压缩为可判定签名。"""

    @staticmethod
    def compress(value: Any, type_name: str = "",
                 inputs: Optional[dict] = None) -> Signature:
        """将值压缩为签名。

        Args:
            value: 要签名的值
            type_name: 类型名
            inputs: 输入参数

        Returns:
            签名
        """
        val_str = str(value)
        sig = Signature(
            type_name=type_name,
            value_hash=hashlib.sha256(val_str.encode()).hexdigest(),
            input_hash=hashlib.sha256(
                json.dumps(inputs or {}, sort_keys=True).encode()
            ).hexdigest(),
            token_count=len(val_str.split()),
        )
        # 信息熵近似
        sig.entropy = SignatureCompressor._estimate_entropy(val_str)
        return sig

    @staticmethod
    def _estimate_entropy(text: str) -> float:
        """估计字符串的信息熵 (shannon entropy)。"""
        if not text:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def similarity(a: Signature, b: Signature) -> float:
        """计算两个签名的相似度 [0, 1]。"""
        score = 0.0
        if a.type_name == b.type_name:
            score += 0.3
        if a.value_hash == b.value_hash:
            score += 0.4
        if abs(a.entropy - b.entropy) < 1.0:
            score += 0.15
        if abs(a.token_count - b.token_count) / max(a.token_count, b.token_count, 1) < 0.3:
            score += 0.15
        return score


# ── Entropy Meter ───────────────────────────────────────────────────

class EntropyMeter:
    """信息熵测量器 — 信息守恒检查。"""

    @staticmethod
    def measure(value: Any) -> float:
        """测量值的信息量。

        信息量 = 字符串长度 × 字符熵 + 结构化复杂度。
        """
        val_str = str(value)
        length = len(val_str)
        if length == 0:
            return 0.0
        char_entropy = SignatureCompressor._estimate_entropy(val_str)
        base = length * char_entropy / 8  # bits
        # 结构复杂度加成
        if isinstance(value, dict):
            base += len(value) * 2
        elif isinstance(value, list):
            base += len(value) * 1.5
        return base

    @staticmethod
    def check_conservation(output_value: Any,
                           input_values: List[Any],
                           epsilon: float = 0.2) -> Tuple[bool, float]:
        """信息守恒检查：输出信息量 ≤ 输入信息量 × (1 + ε)。

        Args:
            output_value: 输出值
            input_values: 输入值列表
            epsilon: 容忍系数（默认 0.2 = 允许 20% 膨胀）

        Returns:
            (conserved: bool, ratio: float)
        """
        output_info = EntropyMeter.measure(output_value)
        input_info = sum(EntropyMeter.measure(v) for v in input_values)

        if input_info == 0:
            return output_info == 0, 0.0

        ratio = output_info / input_info
        return ratio <= 1.0 + epsilon, ratio

    @staticmethod
    def check_repetition(output: str, inputs: List[str],
                         threshold: float = 0.85) -> Tuple[bool, float]:
        """检查输出是否只是输入的重复（投票放大幻觉检测）。

        Returns:
            (is_repetition: bool, similarity: float)
        """
        if not output or not inputs:
            return False, 0.0

        # 对每个输入计算 Jaccard 相似度
        output_tokens = set(output.lower().split())
        if not output_tokens:
            return False, 0.0

        max_sim = 0.0
        for inp in inputs:
            inp_tokens = set(str(inp).lower().split())
            if not inp_tokens:
                continue
            intersection = output_tokens & inp_tokens
            union = output_tokens | inp_tokens
            sim = len(intersection) / len(union) if union else 0
            max_sim = max(max_sim, sim)

        return max_sim >= threshold, max_sim


# ── Layer 1: Generator Constraint ──────────────────────────────────

def check_generator_constraint(output: Any, template: str = "",
                               expected_type: str = "str",
                               param_count: int = 0) -> LayerResult:
    """第①层：生成式约束 — 检查输出是否在模板约束范围内。

    Args:
        output: LLM 输出
        template: 生成模板描述
        expected_type: 期望输出类型
        param_count: 期望输出参数数量（用于结构化输出）

    Returns:
        验证结果
    """
    risk = 0.0
    issues = []

    # 1. 类型约束
    out_str = str(output)
    type_checks = {
        "str": lambda v: isinstance(v, str),
        "int": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "bool": lambda v: isinstance(v, bool),
        "list": lambda v: isinstance(v, list),
        "flag": lambda v: "flag{" in str(v).lower() or "ctf{" in str(v).lower(),
        "ip": lambda v: bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", str(v))),
    }

    checker = type_checks.get(expected_type)
    if checker and not checker(output):
        risk += 0.4
        issues.append(f"类型约束: 期望 {expected_type}, 实际 {type(output).__name__}")

    # 2. 空值检查（LLM 输出为空的典型幻觉）
    if output is None or out_str == "" or out_str == "None":
        risk += 0.5
        issues.append("空值 — LLM 可能无法回答")

    # 3. 长度合理性
    if expected_type == "flag" and len(out_str) > 500:
        risk += 0.3
        issues.append(f"flag 过长 ({len(out_str)} chars)")

    if expected_type == "ip" and len(out_str) > 15:
        risk += 0.2
        issues.append(f"IP 格式异常: {out_str}")

    # 4. 参数数量约束
    if param_count > 0 and isinstance(output, list):
        if len(output) != param_count:
            risk += 0.2
            issues.append(f"参数数量不匹配: 期望 {param_count}, 实际 {len(output)}")

    return LayerResult(
        passed=risk < 0.5,
        risk=min(risk, 1.0),
        detail="; ".join(issues) if issues else "生成式约束通过",
        layer=1,
    )


# ── Layer 2: Discriminant Algebra ──────────────────────────────────

DISCRIMINANT_RULES: Dict[str, Callable[[Any, dict], bool]] = {}


def register_discriminant(operation: str,
                           fn: Callable[[Any, dict], bool]) -> None:
    """注册语义验证函数。

    Args:
        operation: 操作名
        fn: (output, inputs) → bool
    """
    DISCRIMINANT_RULES[operation] = fn


def check_discriminant(output: Any, inputs: dict,
                        operation: str = "") -> LayerResult:
    """第②层：判别式代数 — 纯算法验证 (inputs, output) → bool。

    Args:
        output: 输出值
        inputs: 输入参数字典
        operation: 操作名

    Returns:
        验证结果
    """
    # Built-in rules
    op_lower = operation.lower()
    risk = 0.0
    issues = []

    # 1. grep — output 必须包含 pattern
    if "grep" in op_lower:
        pattern = inputs.get("pattern", "")
        if pattern and isinstance(output, str):
            if pattern not in output:
                risk += 0.6
                issues.append(f"grep 输出不含 '{pattern}'")

    # 2. fetch/http — 非空且不含错误关键词
    if "fetch" in op_lower or "http" in op_lower or "curl" in op_lower:
        out_str = str(output)
        if not out_str:
            risk += 0.7
            issues.append("HTTP 返回空")
        elif any(kw in out_str.lower() for kw in ["error", "timeout", "refused",
                                                    "not found", "404", "500"]):
            risk += 0.3
            issues.append("响应含异常状态")

    # 3. hash — 输出必须匹配哈希格式
    if "hash" in op_lower or "md5" in op_lower or "sha" in op_lower:
        out_str = str(output).strip()
        if not re.match(r"^[a-fA-F0-9]{32,}$", out_str):
            risk += 0.5
            issues.append("输出不是合法哈希值")

    # 4. decode — 输出必须不同于输入
    if "decode" in op_lower or "parse" in op_lower:
        input_val = str(list(inputs.values())[0]) if inputs else ""
        if str(output) == input_val:
            risk += 0.4
            issues.append("解码输出与输入相同（可能未解码）")

    # 5. Custom rules from registry
    for key, fn in DISCRIMINANT_RULES.items():
        if key in op_lower or op_lower in key:
            if not fn(output, inputs):
                risk += 0.5
                issues.append(f"自定义验证规则 '{key}' 未通过")

    return LayerResult(
        passed=risk < 0.5,
        risk=min(risk, 1.0),
        detail="; ".join(issues) if issues else "判别式代数通过",
        layer=2,
    )


# ── Layer 3: Information Conservation ──────────────────────────────

def check_information_conservation(output_value: Any,
                                    input_values: List[Any],
                                    epsilon: float = 0.2) -> LayerResult:
    """第③层：信息守恒 — 产物信息量不能超过源信息量 + ε。

    Args:
        output_value: 输出值
        input_values: 输入值列表
        epsilon: 容忍系数

    Returns:
        验证结果
    """
    conserved, ratio = EntropyMeter.check_conservation(
        output_value, input_values, epsilon
    )

    # 检查重复
    inp_strs = [str(v) for v in input_values]
    is_repetition, similarity = EntropyMeter.check_repetition(
        str(output_value), inp_strs
    )

    risk = 0.0
    issues = []

    if not conserved:
        risk += 0.5
        issues.append(f"信息量膨胀 (ratio={ratio:.2f}, ε={epsilon})")

    if is_repetition:
        risk += 0.4
        issues.append(f"输出是输入的重复 (相似度={similarity:.0%}) — "
                       f"可能为投票放大幻觉")

    return LayerResult(
        passed=risk < 0.5,
        risk=min(risk, 1.0),
        detail="; ".join(issues) if issues
               else f"信息守恒通过 (ratio={ratio:.2f})",
        layer=3,
    )


# ── Layer 4: Bidirectional Convergence ─────────────────────────────

def check_bidirectional_convergence(output: Any,
                                     backward_goals: Optional[List[str]] = None,
                                     forward_givens: Optional[List[str]] = None,
                                     threshold: float = 0.1) -> LayerResult:
    """第④层：双向乘积衰减 — P(假汇合) = P(A 幻觉) × P(B 兼容幻觉)。

    两个不可靠 LLM 的交叉验证将不可靠性指数级降低。

    Args:
        output: 输出值
        backward_goals: 向后目标列表
        forward_givens: 向前已知条件列表
        threshold: 可接受的风险阈值

    Returns:
        验证结果
    """
    risk = 0.0
    issues = []

    if not backward_goals and not forward_givens:
        return LayerResult(
            passed=True, risk=0.0,
            detail="无双向数据 — 仅单向验证",
            layer=4,
        )

    # 估计 backward 幻觉率（基于目标复杂度）
    b_hallucination_rate = 0.0
    if backward_goals:
        total_complexity = sum(len(g.split()) for g in backward_goals)
        b_hallucination_rate = min(0.5, total_complexity / 100)

    # 估计 forward 幻觉率
    f_hallucination_rate = 0.0
    if forward_givens:
        f_hallucination_rate = min(0.4, len(forward_givens) / 20)

    # 乘积衰减 — 核心公式
    if b_hallucination_rate > 0 and f_hallucination_rate > 0:
        joint_hallucination = b_hallucination_rate * f_hallucination_rate
        risk = joint_hallucination
    else:
        risk = b_hallucination_rate or f_hallucination_rate or 0.0

    if risk > threshold:
        issues.append(
            f"双向交叉验证风险={risk:.3f} (P(backward幻觉)={b_hallucination_rate:.3f}, "
            f"P(forward兼容幻觉)={f_hallucination_rate:.3f})"
        )

    return LayerResult(
        passed=risk <= threshold,
        risk=min(risk, 1.0),
        detail="; ".join(issues) if issues
               else f"双向乘积衰减通过 (joint_risk={risk:.4f})",
        layer=4,
    )


# ── Guard Config ───────────────────────────────────────────────────

@dataclass
class GuardConfig:
    """抗幻觉守卫配置。"""
    enable_layer1: bool = True    # 生成式约束
    enable_layer2: bool = True    # 判别式代数
    enable_layer3: bool = True    # 信息守恒
    enable_layer4: bool = True    # 双向乘积衰减
    info_epsilon: float = 0.2     # 信息守恒容忍系数
    convergence_threshold: float = 0.1  # 双向风险阈值

    @classmethod
    def strict(cls) -> GuardConfig:
        """严格模式：低容忍、全启用。"""
        return cls(info_epsilon=0.1, convergence_threshold=0.05)

    @classmethod
    def relaxed(cls) -> GuardConfig:
        """宽松模式：高容忍（调试用）。"""
        return cls(info_epsilon=0.5, convergence_threshold=0.3)

    def to_dict(self) -> dict:
        return {
            "layers": {f"layer{i}": getattr(self, f"enable_layer{i}")
                       for i in range(1, 5)},
            "info_epsilon": self.info_epsilon,
            "convergence_threshold": self.convergence_threshold,
        }


# ── Main Guard ─────────────────────────────────────────────────────

class HallucinationGuard:
    """抗幻觉守卫 — 四层体系集中控制器。

    用法:
        guard = HallucinationGuard()

        # 评估单个输出
        verdict = guard.evaluate(
            output="flag{abc123}",
            inputs={"pattern": "flag"},
            expected_type="flag",
            operation="grep",
        )

        # 批量评估
        results = guard.evaluate_all([
            {"output": "port 80 open", "operation": "port_scan"},
            {"output": "admin", "operation": "grep", "inputs": {"pattern": "admin"}},
        ])
    """

    def __init__(self, config: Optional[GuardConfig] = None):
        self.config = config or GuardConfig()
        self.history: List[GuardVerdict] = []

    def evaluate(self, output: Any,
                 inputs: Optional[dict] = None,
                 expected_type: str = "str",
                 operation: str = "",
                 input_values: Optional[List[Any]] = None,
                 backward_goals: Optional[List[str]] = None,
                 forward_givens: Optional[List[str]] = None) -> GuardVerdict:
        """对输出运行全部四层抗幻觉检查。

        Args:
            output: LLM 输出值
            inputs: 输入参数字典
            expected_type: 期望类型
            operation: 操作名
            input_values: 输入值列表（信息守恒用）
            backward_goals: 向后目标列表（双向乘积衰减用）
            forward_givens: 向前已知条件列表（双向乘积衰减用）

        Returns:
            验证结果
        """
        # Normalize inputs: accept dict, string (treated as single input), or None
        if inputs is None:
            inputs = {}
        elif not isinstance(inputs, dict):
            # Single scalar input → wrap in dict for uniform handling
            inputs = {"value": inputs}
        input_values = input_values or list(inputs.values())
        layers: List[LayerResult] = []
        total_risk = 0.0
        active_layers = 0

        # Layer 1
        if self.config.enable_layer1:
            l1 = check_generator_constraint(output, expected_type=expected_type)
            layers.append(l1)
            total_risk += l1.risk
            active_layers += 1

        # Layer 2
        if self.config.enable_layer2:
            l2 = check_discriminant(output, inputs, operation=operation)
            layers.append(l2)
            total_risk += l2.risk
            active_layers += 1

        # Layer 3
        if self.config.enable_layer3:
            l3 = check_information_conservation(
                output, input_values, epsilon=self.config.info_epsilon
            )
            layers.append(l3)
            total_risk += l3.risk
            active_layers += 1

        # Layer 4
        if self.config.enable_layer4:
            l4 = check_bidirectional_convergence(
                output,
                backward_goals=backward_goals,
                forward_givens=forward_givens,
                threshold=self.config.convergence_threshold,
            )
            layers.append(l4)
            total_risk += l4.risk
            active_layers += 1

        # Aggregate
        avg_risk = total_risk / max(active_layers, 1)
        failed_layers = sum(1 for l in layers if not l.passed)
        warned_layers = sum(1 for l in layers if l.risk > 0.3 and l.passed)

        # Risk level
        if failed_layers >= 2:
            level = RiskLevel.CRITICAL
        elif failed_layers == 1:
            level = RiskLevel.HIGH
        elif warned_layers >= 2:
            level = RiskLevel.MEDIUM
        elif warned_layers == 1:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.SAFE

        # Reason
        failed_details = [l.detail for l in layers if not l.passed]
        reason = "; ".join(failed_details) if failed_details else "全部四层验证通过"

        verdict = GuardVerdict(
            risk_level=level,
            risk_score=round(avg_risk, 3),
            confidence=round(1.0 - avg_risk, 3),
            reason=reason,
            layers=layers,
        )

        self.history.append(verdict)
        return verdict

    def evaluate_all(self, items: List[dict]) -> List[GuardVerdict]:
        """批量评估多个输出。"""
        return [self.evaluate(**item) for item in items]

    def summary(self) -> str:
        """历史汇总。"""
        if not self.history:
            return "无评估记录"
        total = len(self.history)
        safe = sum(1 for v in self.history if v.risk_level.is_acceptable)
        critical = sum(1 for v in self.history if v.risk_level == RiskLevel.CRITICAL)
        avg_risk = sum(v.risk_score for v in self.history) / total

        return (
            f"抗幻觉守卫评估汇总 ({total} 次)\n"
            f"  可接受: {safe}/{total} ({safe/total*100:.0f}%)\n"
            f"  高风险: {critical}/{total}\n"
            f"  平均风险: {avg_risk:.3f}\n"
            f"  配置: {json.dumps(self.config.to_dict(), ensure_ascii=False)}"
        )


# ── CLI ─────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(prog="antihallucination",
                                     description="算法抗幻觉模块 CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_eval = sub.add_parser("eval", help="评估输出风险")
    p_eval.add_argument("output", help="要评估的输出值")
    p_eval.add_argument("--type", default="str", help="期望类型")
    p_eval.add_argument("--op", default="", help="操作名")
    p_eval.add_argument("--input", "-i", action="append", default=[],
                        help="输入值 (可多次)")
    p_eval.add_argument("--strict", action="store_true", help="严格模式")
    p_eval.add_argument("--json", action="store_true", help="JSON 输出")

    p_gate = sub.add_parser("gate", help="事实断言门控 (第⑤层)")
    p_gate.add_argument("text", help="要门控的分析文本")
    p_gate.add_argument("--domain", default=None, help="证据域 (vuln_miner 等)")
    p_gate.add_argument("--strict", action="store_true", help="严格模式")
    p_gate.add_argument("--json", action="store_true", help="JSON 输出")

    p_verify = sub.add_parser("verify", help="断言验证 (第⑤层)")
    p_verify.add_argument("text", help="要验证的分析文本")
    p_verify.add_argument("--domain", default=None, help="证据域")
    p_verify.add_argument("--json", action="store_true", help="JSON 输出")

    args = parser.parse_args()

    if args.cmd == "eval":
        config = GuardConfig.strict() if args.strict else GuardConfig()
        guard = HallucinationGuard(config=config)
        inputs = {f"arg{i}": v for i, v in enumerate(args.input)}
        verdict = guard.evaluate(
            output=args.output,
            inputs=inputs if inputs else None,
            expected_type=args.type,
            operation=args.op,
            input_values=args.input or None,
        )
        if args.json:
            print(json.dumps(verdict.to_dict(), ensure_ascii=False, indent=2))
        else:
            print(f"风险等级: {verdict.risk_level.value.upper()}")
            print(f"风险评分: {verdict.risk_score:.3f}")
            print(f"置信度: {verdict.confidence:.3f}")
            print(f"判定: {verdict.reason}")
            for l in verdict.layers:
                icon = "PASS" if l.passed else "FAIL"
                print(f"  L{l.layer}: [{icon}] risk={l.risk:.2f} {l.detail[:80]}")

    elif args.cmd == "gate":
        gate = FactGate(domain=args.domain, strict=args.strict)
        report = gate.gate(args.text, domain=args.domain)
        if args.json:
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        else:
            print(report.summary())
            print()
            print(report.filtered_output or "(无放行断言)")

    elif args.cmd == "verify":
        gate = FactGate(domain=args.domain)
        report = gate.gate(args.text, domain=args.domain)
        if args.json:
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        else:
            for v in report.claims:
                icon = {"verified": "✓", "contradicted": "✗", "unverifiable": "?"}
                print(f"{icon.get(v.status, '?')} [{v.claim.claim_type:11s}] "
                      f"{v.claim.subject} → {v.status}")
                if v.corrected:
                    print(f"    纠正: {v.corrected}")
                for e in v.evidence:
                    print(f"    证据: {e.source} {e.ref}")


if __name__ == "__main__":
    main()


__all__ = ['EntropyMeter', 'GuardConfig', 'GuardVerdict', 'HallucinationGuard', 'LayerResult', 'RiskLevel', 'Signature', 'SignatureCompressor', 'check_bidirectional_convergence', 'check_discriminant', 'check_generator_constraint', 'check_information_conservation', 'register_discriminant', 'Claim', 'ClaimExtractor', 'ClaimVerdict', 'Evidence', 'EvidenceBinder', 'FactGate', 'FactVerifier', 'GateReport', 'default_providers', 'register_provider']