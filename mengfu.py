"""凭据治理规范 —— 道统算子谱（mengfu）
道统出处：勋藏盟府，司盟之府
工程映射：密钥治理政策层，永不存真实钥匙
生长纪律：本地生长自由，推送远端需治理决议发令。
# 生长记录 2026-11-02：内核 M1 落地，用例 5 条全绿
"""

import re

# 疑似真实密钥形态：长度≥32 的随机 hex/base64 串
_HEX_B64_RE = re.compile(r"^[0-9a-fA-F+/=_-]{32,}$")
_REQUIRED_FIELDS = ("rotation_days", "scope", "storage")


class VaultPolicy:
    """盟府：凭据只登记引用（路径/环境变量名），永不存真实钥匙。"""

    def __init__(self):
        self._refs = {}       # ref -> policy dict（只存政策与引用）

    def register(self, ref: str, policy: dict):
        """登记凭据引用与治理政策。

        - ref 必须是引用名（路径、环境变量名等），不得是疑似真实密钥形态；
        - 政策缺必需字段（rotation_days/scope/storage）判不通过。
        """
        if not isinstance(ref, str) or not ref.strip():
            raise ValueError("ref 必须是非空引用名")
        if _HEX_B64_RE.match(ref) and len(ref) >= 32:
            raise ValueError("ref 形似真实密钥（长随机串），盟府只收引用不收钥匙")
        missing = [f for f in _REQUIRED_FIELDS if f not in policy]
        if missing:
            raise ValueError(f"政策缺必需字段：{','.join(missing)}")
        self._refs[ref] = dict(policy)
        return ref

    def check(self, ref: str) -> bool:
        """校验登记在案且政策字段完整。"""
        return ref in self._refs and all(f in self._refs[ref] for f in _REQUIRED_FIELDS)

    def list_refs(self) -> list:
        """概览：只回引用名，不回显任何政策值或密钥内容。"""
        return list(self._refs.keys())

    def describe(self) -> dict:
        return {"name": "mengfu", "role": "密钥治理政策层，永不存真实钥匙", "stage": "m1"}
