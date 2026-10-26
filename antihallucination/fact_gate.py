"""第⑤层：事实断言裁决 (Fact Gate) — 断言级可验证。

前四层只验证"格式"，这一层回答"模型说的事跟外部真相一致吗"。

把 LLM 输出拆成原子断言，逐条绑定外部 ground truth，确定性裁决。
核心保证：**输出里以事实身份呈现的断言 ⊆ 已验证断言集**（结构保证，非概率保证）。

```
LLM 输出文本
  → ClaimExtractor: 拆成原子断言 + 分类（确定性正则优先，LLM 可选增强）
  → EvidenceBinder: 按类型选 provider 取外部证据
  → FactVerifier:  确定性裁决 (verified / contradicted / unverifiable)
  → Gate:          分级门控 → 干净输出 + GateReport
```

断言分类 → 门控策略:
    fact         CVE/影响版本/IP端口状态/文件内容 —— 无证据即删除/拒答
    observation  工具输出、实测结果              —— 无证据即删除
    conclusion   漏洞可利用性、攻击链推断        —— 无证据降级标注「未验证假设」
    action       升级/加固建议                  —— 保留但标注

裁决状态（确定性）:
    verified      证据明确支持 → 放行 + 证据引用
    contradicted  证据明确相反 → 纠正后输出
    unverifiable  找不到证据  → 按门控策略处理

确定性优先原则：提取用正则锚点（不引入新幻觉源），裁决用硬匹配；
"证据是否存在"是独立检查，不经过 LLM —— 找不到证据 = unverifiable。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# ── Data models ──────────────────────────────────────────────────────

@dataclass
class Claim:
    """原子断言。"""
    text: str = ""          # 断言原文（所在句子）
    claim_type: str = ""    # fact / observation / conclusion / action
    subject: str = ""       # 主语锚点 (CVE-2021-44228 / 10.0.0.5 / log4j)
    predicate: str = ""     # 谓词 (影响版本 / 开放端口 / 存在漏洞)
    subject_kind: str = ""  # 锚点类型 (cve/ip/port/version/filename) — 路由用


@dataclass
class Evidence:
    """外部证据。"""
    source: str = ""        # kb_entry / cve_db / tool_stdout / file_content / math_verify
    value: str = ""         # 证据原文
    ref: str = ""           # 出处 (文件路径 / 命令 / DB 记录)
    supports: bool = False  # 是否支持断言（硬匹配结果）

    def to_dict(self) -> dict:
        return {"source": self.source, "ref": self.ref,
                "supports": self.supports, "value": self.value[:300]}


@dataclass
class ClaimVerdict:
    """单条断言的裁决。"""
    claim: Claim
    status: str = "unverifiable"   # verified / contradicted / unverifiable
    evidence: List[Evidence] = field(default_factory=list)
    corrected: str = ""            # contradicted 时给出纠正

    def to_dict(self) -> dict:
        return {
            "text": self.claim.text,
            "type": self.claim.claim_type,
            "subject": self.claim.subject,
            "predicate": self.claim.predicate,
            "status": self.status,
            "corrected": self.corrected,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class GateReport:
    """门控报告。"""
    claims: List[ClaimVerdict] = field(default_factory=list)
    filtered_output: str = ""
    factual_claims_verified: bool = True   # 所有 fact/observation 断言都有 verified 证据?
    domain: str = ""

    @property
    def verified_count(self) -> int:
        return sum(1 for v in self.claims if v.status == "verified")

    @property
    def contradicted_count(self) -> int:
        return sum(1 for v in self.claims if v.status == "contradicted")

    @property
    def unverifiable_count(self) -> int:
        return sum(1 for v in self.claims if v.status == "unverifiable")

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "total": len(self.claims),
            "verified": self.verified_count,
            "contradicted": self.contradicted_count,
            "unverifiable": self.unverifiable_count,
            "factual_claims_verified": self.factual_claims_verified,
            "claims": [v.to_dict() for v in self.claims],
            "filtered_output": self.filtered_output,
        }

    def summary(self) -> str:
        return (
            f"FactGate[{self.domain or '-'}] "
            f"{self.verified_count} verified / "
            f"{self.contradicted_count} contradicted / "
            f"{self.unverifiable_count} unverifiable | "
            f"factual_verified={self.factual_claims_verified}"
        )


# ── Extraction anchors (deterministic regex, priority-ordered) ──────

_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_PORT = re.compile(
    r"\b(?:port|端口)\s*[:#]?\s*(?P<port>\d{1,5})\b"   # port 80 / 端口 80
    r"|"
    r"\b(?P<port2>\d{1,5})\s*(?:port|端口)\b",          # 80 端口 / 80 port
    re.I,
)
_RE_FILENAME = re.compile(
    r"\b[\w./\\-]+\.(?:apk|ipa|aab|dex|smali|pcap|pcapng|cap|exe|dll|elf|so|"
    r"pem|crt|cer|key|E01|e01|dmp|mem|vmem|bin|jar|py|go|rs|c|h|sh|ps1|"
    r"json|yaml|yml|md|txt)\b",
    re.I,
)
_RE_VERSION = re.compile(r"\b\d+\.\d+(?:\.\d+)*(?:[-a-zA-Z0-9_.]*)\b")

# Claim-type keyword markers (deterministic classification)
_OBSERVATION_MARKERS = ("扫描结果", "实测", "输出", "返回", "探测", "found",
                        "scan result", "观察", "测得", "响应")
_CONCLUSION_MARKERS = ("可利用", "exploit", "exploitable", "rce", "远程代码执行",
                       "任意代码执行", "提权", "攻击链", "注入", "触发", "导致",
                       "存在漏洞", "存在反序列化")
_ACTION_MARKERS = ("建议", "应", "需要", "升级", "加固", "打补丁", "patch",
                   "upgrade", "修复", "配置", "禁用", "recommend", "mitigate")


def _split_sentences(text: str) -> List[Tuple[int, int, str]]:
    """切分句子，返回 (start, end, stripped) 列表。"""
    spans: List[Tuple[int, int, str]] = []
    n = len(text)
    start = 0
    for i in range(n):
        if text[i] in "。！？!?;\n":
            seg = text[start:i + 1].strip()
            if seg:
                spans.append((start, i + 1, seg))
            start = i + 1
    if start < n:
        seg = text[start:].strip()
        if seg:
            spans.append((start, n, seg))
    return spans


def _sentence_for(spans: List[Tuple[int, int, str]], pos: int) -> str:
    for s, e, seg in spans:
        if s <= pos < e:
            return seg
    return ""


def _classify(sentence: str, kind: str) -> str:
    """按锚点类型 + 上下文关键词分类 claim_type。"""
    if kind == "filename":
        return "fact"  # 文件内容类默认 fact
    for kw in _CONCLUSION_MARKERS:
        if kw.lower() in sentence.lower():
            return "conclusion"
    for kw in _ACTION_MARKERS:
        if kw.lower() in sentence.lower():
            return "action"
    for kw in _OBSERVATION_MARKERS:
        if kw.lower() in sentence.lower():
            return "observation"
    return "fact"  # cve/ip/port/version 默认 fact


def _predicate(kind: str, sentence: str, anchor: str) -> str:
    if kind == "cve":
        return "存在漏洞"
    if kind == "ip":
        return "IP 地址"
    if kind == "port":
        if re.search(r"closed|filtered|关闭|过滤", sentence, re.I):
            return "关闭端口"
        return "开放端口"
    if kind == "version":
        return "影响版本"
    if kind == "filename":
        return "文件内容"
    return ""


def _port_subject(sentence: str, port_num: str) -> str:
    ip_m = _RE_IP.search(sentence)
    if ip_m:
        return f"{ip_m.group(0)}:{port_num}"
    return f"port {port_num}"


# ── Claim Extractor ──────────────────────────────────────────────────

class ClaimExtractor:
    """拆 LLM 输出为原子断言。纯正则，确定性，不引入新幻觉源。"""

    def extract(self, text: str) -> List[Claim]:
        if not text:
            return []
        spans = _split_sentences(text)
        seen: set = set()
        claims: List[Claim] = []
        covered: List[Tuple[int, int]] = []   # 高优先级锚点已占用的字符区间

        def _anchor(kind: str, anchor: str, sentence: str) -> str:
            if kind == "port":
                return _port_subject(sentence, anchor)
            return anchor

        # 高优先级锚点：cve / ip / port / filename
        for kind, pattern in (("cve", _RE_CVE), ("ip", _RE_IP),
                              ("port", _RE_PORT), ("filename", _RE_FILENAME)):
            for m in pattern.finditer(text):
                sentence = _sentence_for(spans, m.start())
                if not sentence:
                    continue
                if kind == "port":
                    anchor = m.group("port") or m.group("port2")
                else:
                    anchor = m.group(0)
                subject = _anchor(kind, anchor, sentence)
                key = (kind, subject, sentence)
                if key in seen:
                    continue
                seen.add(key)
                covered.append((m.start(), m.end()))
                claims.append(Claim(
                    text=sentence,
                    claim_type=_classify(sentence, kind),
                    subject=subject,
                    predicate=_predicate(kind, sentence, anchor),
                    subject_kind=kind,
                ))

        # 低优先级锚点：version（跳过与 ip/port/cve 重叠的版本号，如 10.0.0.5）
        for m in _RE_VERSION.finditer(text):
            if any(s <= m.start() and m.end() <= e for s, e in covered):
                continue
            sentence = _sentence_for(spans, m.start())
            if not sentence:
                continue
            subject = m.group(0)
            key = ("version", subject, sentence)
            if key in seen:
                continue
            seen.add(key)
            claims.append(Claim(
                text=sentence,
                claim_type=_classify(sentence, "version"),
                subject=subject,
                predicate=_predicate("version", sentence, subject),
                subject_kind="version",
            ))
        return claims


# ── Hard-match helpers (deterministic verdict) ───────────────────────

def _hard_match(claim: Claim, value: str) -> bool:
    """确定性硬匹配：断言主语是否出现在证据里。"""
    value_low = (value or "").lower()
    if claim.subject_kind == "port":
        port_m = re.search(r"(\d{1,5})\s*$", claim.subject)
        if port_m and port_m.group(1) not in value:
            return False
        if claim.predicate == "开放端口":
            return "open" in value_low or "开放" in value
        if claim.predicate == "关闭端口":
            return ("closed" in value_low or "filtered" in value_low
                    or "关闭" in value)
        return True
    subject = (claim.subject or "").lower()
    return bool(subject) and subject in value_low


def _contradiction(claim: Claim, value: str) -> str:
    """证据存在但与谓词相反时，给出纠正文本（否则 None）。"""
    value_low = (value or "").lower()
    if claim.subject_kind == "port":
        if claim.predicate == "开放端口" and any(
                w in value_low for w in ("closed", "filtered", "关闭")):
            return f"{claim.subject} 实际为关闭/过滤状态"
        if claim.predicate == "关闭端口" and ("open" in value_low or "开放" in value):
            return f"{claim.subject} 实际为开放状态"
    if claim.subject_kind == "cve":
        if "not affected" in value_low or "不受影响" in value:
            return f"{claim.subject} 不受影响"
    return ""


# ── Evidence providers (plugin-ized) ─────────────────────────────────

ProviderFn = Callable[[Claim, Dict[str, Any]], Optional[Evidence]]


def _provider_tool(claim: Claim, context: dict) -> Optional[Evidence]:
    """工具实测输出证据（报告文件或注入文本）。"""
    text = context.get("report_text") or ""
    if not text and context.get("report_path"):
        try:
            text = Path(context["report_path"]).read_text(encoding="utf-8",
                                                          errors="ignore")
        except Exception as _e:
            logging.getLogger(__name__).warning("evidence fetch failed", exc_info=True)
            return None
    if not text:
        return None
    if _hard_match(claim, text):
        return Evidence("tool_stdout", text,
                        str(context.get("report_path") or "tool stdout"), True)
    contra = _contradiction(claim, text)
    if contra:
        return Evidence("tool_stdout", text,
                        str(context.get("report_path") or "tool stdout"), False)
    return None


def _provider_file(claim: Claim, context: dict) -> Optional[Evidence]:
    """文件内容证据。"""
    if claim.subject_kind != "filename":
        return None
    path = context.get("target") or claim.subject
    p = Path(path)
    if not p.exists():
        return None
    try:
        content = p.read_text(encoding="utf-8", errors="ignore")
    except Exception as _e:
        logging.getLogger(__name__).warning("evidence fetch failed", exc_info=True)
        return None
    return Evidence("file_content", content[:2000], str(p), True)


def _provider_math(claim: Claim, context: dict) -> Optional[Evidence]:
    """数学验证证据（context 注入已算好的确定性结果）。"""
    result = context.get("math_result")
    if not isinstance(result, dict) or claim.subject not in result:
        return None
    return Evidence("math_verify", f"{claim.subject}={result[claim.subject]}",
                    f"math:{claim.subject}", True)


PROVIDER_REGISTRY: Dict[str, ProviderFn] = {}


def register_provider(name: str, fn: ProviderFn) -> None:
    """注册自定义证据 provider（仿 register_discriminant 模式）。"""
    PROVIDER_REGISTRY[name] = fn


def default_providers() -> Dict[str, ProviderFn]:
    """内置 provider 注册表（可被 register_provider 覆盖/扩展）。"""
    builtins: Dict[str, ProviderFn] = {
        "tool_stdout": _provider_tool,
        "file_content": _provider_file,
        "math_verify": _provider_math,
    }
    merged = dict(builtins)
    merged.update(PROVIDER_REGISTRY)
    return merged


# ── Evidence Binder ──────────────────────────────────────────────────

# 锚点类型 → 候选 provider（按序尝试）
_ROUTING = {
    "cve": ["cve_db", "kb_entry"],
    "ip": ["tool_stdout", "file_content"],
    "port": ["tool_stdout"],
    "version": ["kb_entry", "cve_db"],
    "filename": ["file_content", "tool_stdout"],
}


class EvidenceBinder:
    """按 claim_type/subject 路由到 provider 取证据。"""

    def __init__(self, providers: Optional[Dict[str, ProviderFn]] = None):
        self.providers = providers or default_providers()

    def bind(self, claim: Claim, context: Optional[dict] = None) -> List[Evidence]:
        context = context or {}
        evidence: List[Evidence] = []
        for name in _ROUTING.get(claim.subject_kind, []):
            fn = self.providers.get(name)
            if not fn:
                continue
            try:
                ev = fn(claim, context)
            except Exception:
                ev = None
            if ev is not None:
                evidence.append(ev)
        return evidence


# ── Fact Verifier ────────────────────────────────────────────────────

class FactVerifier:
    """确定性裁决：硬匹配，不经过 LLM。"""

    @staticmethod
    def verify(claim: Claim, evidence: List[Evidence]) -> ClaimVerdict:
        supports = [e for e in evidence if e.supports]
        if supports:
            return ClaimVerdict(claim, "verified", evidence, "")
        contradicts = [e for e in evidence if not e.supports]
        if contradicts:
            corrected = _contradiction(claim, contradicts[0].value)
            if not corrected:
                corrected = contradicts[0].value[:200]
            return ClaimVerdict(claim, "contradicted", evidence, corrected)
        return ClaimVerdict(claim, "unverifiable", evidence, "")


# ── Gating ───────────────────────────────────────────────────────────

def _apply_gate(text: str, verdicts: List[ClaimVerdict]) -> str:
    """分级门控：删未验证 fact/observation，标注 conclusion/action，纠正 contradicted。"""
    drop: set = set()
    annotations: List[str] = []
    seen: set = set()
    for v in verdicts:
        c = v.claim
        sent = c.text.strip()
        if c.claim_type in ("fact", "observation"):
            if v.status == "contradicted":
                drop.add(sent)
                if sent not in seen:
                    annotations.append(f"[纠正] {sent} → {v.corrected}")
                    seen.add(sent)
            elif v.status == "unverifiable":
                drop.add(sent)
                if sent not in seen:
                    annotations.append(f"[删除·未验证] {c.claim_type}: {sent}")
                    seen.add(sent)
        elif c.claim_type == "conclusion":
            if v.status == "unverifiable" and sent not in seen:
                annotations.append(f"[未验证假设] {sent}")
                seen.add(sent)
        elif c.claim_type == "action":
            if sent not in seen:
                annotations.append(f"[建议] {sent}")
                seen.add(sent)

    # 重建：丢弃被标记的句子，保留其余（含原始空白/顺序）
    out = "".join(text[s:e] for s, e, _ in _split_sentences(text)
                  if text[s:e].strip() not in drop).strip()

    if annotations:
        out = (out + "\n\n" if out else "") + "\n".join(annotations)
    return out


# ── Fact Gate ────────────────────────────────────────────────────────

class FactGate:
    """第⑤层集中控制器：提取 → 绑定 → 裁决 → 门控。"""

    def __init__(self, providers: Optional[Dict[str, ProviderFn]] = None,
                 domain: Optional[str] = None, strict: bool = False):
        self.extractor = ClaimExtractor()
        self.binder = EvidenceBinder(providers)
        self.verifier = FactVerifier()
        self.domain = domain
        self.strict = strict

    def gate(self, text: str, domain: Optional[str] = None,
             strict: Optional[bool] = None,
             context: Optional[dict] = None) -> GateReport:
        domain = domain or self.domain
        strict = self.strict if strict is None else strict
        context = dict(context or {})
        context.setdefault("domain", domain)

        claims = self.extractor.extract(text)
        verdicts = [self.verifier.verify(c, self.binder.bind(c, context))
                    for c in claims]

        factual_verified = all(
            v.status == "verified"
            for v in verdicts
            if v.claim.claim_type in ("fact", "observation")
        )

        return GateReport(
            claims=verdicts,
            filtered_output=_apply_gate(text, verdicts),
            factual_claims_verified=factual_verified,
            domain=domain or "",
        )


__all__ = [
    "Claim", "Evidence", "ClaimVerdict", "GateReport",
    "ClaimExtractor", "EvidenceBinder", "FactVerifier", "FactGate",
    "register_provider", "default_providers",
]
