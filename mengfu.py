"""凭据治理规范 —— 道统算子谱（mengfu）
道统出处：勋藏盟府，司盟之府
工程映射：密钥治理政策层，永不存真实钥匙
生长纪律：本地生长自由，推送远端需治理决议发令。
# 生长记录 2026-11-02：内核 M1 落地，用例 5 条全绿
# 生长记录 2026-11-28：M2 落地——轮换到期体检、注销重发、治理审计簿、
#   泄漏体检（文本扫描只报位置不回显内容）；政策值与注销理由同受钥匙形态检查
"""

import re
import time

# 疑似真实密钥形态：长度≥32 的随机 hex/base64 串
_HEX_B64_RE = re.compile(r"^[0-9a-fA-F+/=_-]{32,}$")
# 泄漏体检用：文本中不限锚点的疑似密钥片段
_SCAN_RE = re.compile(r"[0-9a-fA-F+/=_-]{32,}")
_REQUIRED_FIELDS = ("rotation_days", "scope", "storage")


def _is_key_shaped(value) -> bool:
    """判断单个值是否形似真实密钥（长随机 hex/base64 串）。"""
    return isinstance(value, str) and len(value) >= 32 and bool(_HEX_B64_RE.match(value))


def scan_text(text):
    """泄漏体检：找出文本中疑似真实密钥的片段位置。

    只返回 {"line", "col", "length"}，绝不回显命中内容本身——
    盟府永不转抄钥匙，体检报告同样只给坐标不给内容。
    """
    findings = []
    if not isinstance(text, str) or not text:
        return findings
    for lineno, line in enumerate(text.splitlines(), start=1):
        for m in _SCAN_RE.finditer(line):
            findings.append({"line": lineno, "col": m.start() + 1, "length": m.end() - m.start()})
    return findings


class VaultPolicy:
    """盟府：凭据只登记引用（路径/环境变量名），永不存真实钥匙。"""

    def __init__(self):
        self._refs = {}           # ref -> policy dict（只存政策与引用）
        self._registered_at = {}  # ref -> 登记时刻（epoch 秒）
        self._revoked = {}        # ref -> 注销记录（理由+时刻）
        self._audit = []          # 治理审计簿：只追加，只记动作元数据

    # ---- 内部 ----
    def _log(self, action, ref, detail=""):
        self._audit.append({
            "seq": len(self._audit) + 1,
            "action": action,
            "ref": ref,
            "at": time.time(),
            "detail": detail,
        })

    def _validate(self, ref, policy):
        if not isinstance(ref, str) or not ref.strip():
            raise ValueError("ref 必须是非空引用名")
        if _is_key_shaped(ref):
            raise ValueError("ref 形似真实密钥（长随机串），盟府只收引用不收钥匙")
        if not isinstance(policy, dict):
            raise ValueError("政策必须是字典")
        missing = [f for f in _REQUIRED_FIELDS if f not in policy]
        if missing:
            raise ValueError(f"政策缺必需字段：{','.join(missing)}")
        for k, v in policy.items():
            if _is_key_shaped(v):
                raise ValueError(f"政策字段 {k} 形似真实密钥，盟府只收政策不收钥匙")

    # ---- 登记域 ----
    def register(self, ref: str, policy: dict, registered_at=None):
        """登记凭据引用与治理政策。

        - ref 必须是引用名（路径、环境变量名等），不得是疑似真实密钥形态；
        - 政策缺必需字段（rotation_days/scope/storage）判不通过；
        - 政策值同样不得藏钥匙（M2 起）；
        - 已注销的引用不接受直接 register，须走 reissue() 凭新政策重发。
        """
        self._validate(ref, policy)
        if ref in self._revoked:
            raise ValueError("引用已注销，直接登记不受理；请用 reissue() 凭完整新政策重发")
        self._refs[ref] = dict(policy)
        self._registered_at[ref] = time.time() if registered_at is None else registered_at
        self._log("register", ref)
        return ref

    def check(self, ref: str) -> bool:
        """校验登记在案且政策字段完整（已注销一律 False）。"""
        return ref in self._refs and all(f in self._refs[ref] for f in _REQUIRED_FIELDS)

    def list_refs(self) -> list:
        """概览：只回引用名，不回显任何政策值或密钥内容。"""
        return list(self._refs.keys())

    # ---- 轮换域 ----
    def due_for_rotation(self, ref: str, as_of=None):
        """轮换体检：返回 (是否到期, 剩余天数)。

        剩余天数 = rotation_days - 已登记天数；≤0 即到期应轮换。
        未登记的引用抛 KeyError，不静默。
        """
        if ref not in self._refs:
            raise KeyError(f"引用未登记：{ref}")
        now = time.time() if as_of is None else as_of
        age_days = (now - self._registered_at[ref]) / 86400.0
        remaining = float(self._refs[ref]["rotation_days"]) - age_days
        return (remaining <= 0, remaining)

    # ---- 注销域 ----
    def revoke(self, ref: str, reason: str = "") -> bool:
        """注销引用：从在册册移入注销册，审计留痕。

        - 未登记的引用不可注销；
        - 注销理由同样不得是钥匙形态内容（盟府永不转抄钥匙）。
        """
        if ref not in self._refs:
            raise KeyError(f"引用未登记，无从注销：{ref}")
        if _is_key_shaped(reason):
            raise ValueError("注销理由形似真实密钥，盟府不转抄钥匙")
        del self._refs[ref]
        self._registered_at.pop(ref, None)
        self._revoked[ref] = {"reason": reason, "at": time.time()}
        self._log("revoke", ref, reason)
        return True

    def is_revoked(self, ref: str) -> bool:
        return ref in self._revoked

    def reissue(self, ref: str, policy: dict, registered_at=None):
        """注销后重发：必须提供完整新政策，按新登记时刻重新起算轮换期。"""
        if ref not in self._revoked:
            raise ValueError("引用不在注销册中，直接 register 即可")
        self._validate(ref, policy)
        del self._revoked[ref]
        self._refs[ref] = dict(policy)
        self._registered_at[ref] = time.time() if registered_at is None else registered_at
        self._log("reissue", ref)
        return ref

    # ---- 审计域 ----
    def audit_trail(self) -> list:
        """治理审计簿：seq 从 1 起连续，只含动作元数据，不含政策值与密钥内容。"""
        return [dict(e) for e in self._audit]

    def audit_intact(self) -> bool:
        """审计簿完整性核验：seq 必须从 1 起连续无断链。

        任何删改都会造成 seq 缺号，当场现形；不静默吞掉。
        """
        return [e["seq"] for e in self._audit] == list(range(1, len(self._audit) + 1))

    # ---- 概览 ----
    def export_state(self) -> dict:
        """导出可持久化政策册快照：只有引用、政策字段与注销理由，结构上放不进钥匙。"""
        return {
            "registered": [
                {"ref": ref, "policy": dict(self._refs[ref]), "registered_at": self._registered_at[ref]}
                for ref in self._refs
            ],
            "revoked": [
                {"ref": ref, "reason": rec["reason"]} for ref, rec in self._revoked.items()
            ],
        }

    def describe(self) -> dict:
        return {
            "name": "mengfu",
            "role": "密钥治理政策层，永不存真实钥匙",
            "stage": "m2",
            "registered": len(self._refs),
            "revoked": len(self._revoked),
            "audit_events": len(self._audit),
        }
