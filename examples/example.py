"""盟府 M2 示例：登记 → 轮换体检 → 注销 → 重发 → 审计回看 → 泄漏体检。

运行：python examples/example.py
全程不出现任何真实钥匙：引用是名字，政策是数字与用途描述。
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mengfu import VaultPolicy, scan_text

vault = VaultPolicy()

# 1) 登记：只收引用名 + 治理政策（示例统一以 epoch 0 为登记时刻，方便推演）
vault.register("env/ATOMGIT_TOKEN_PATH", {"rotation_days": 90, "scope": "push", "storage": "kernel-file"},
               registered_at=0)
vault.register("file/.kernel/yuanji.token", {"rotation_days": 30, "scope": "read", "storage": "kernel-file"},
               registered_at=0)
print("在册引用：", vault.list_refs())

# 2) 轮换体检：以第 45 天为观察点，30 天期的已到期
due, remaining = vault.due_for_rotation("file/.kernel/yuanji.token", as_of=45 * 86400)
print(f"30 天期引用第 45 天：到期={due}，剩余 {remaining:.1f} 天")

# 3) 注销 + 重发：轮换落地就是注销旧政策、凭新政策重发
vault.revoke("file/.kernel/yuanji.token", reason="轮换到期")
print("注销后 check：", vault.check("file/.kernel/yuanji.token"))
vault.reissue("file/.kernel/yuanji.token", {"rotation_days": 30, "scope": "read", "storage": "kernel-file"},
              registered_at=45 * 86400)
print("重发后 check：", vault.check("file/.kernel/yuanji.token"))

# 4) 审计回看：每个动作都有 seq，只有元数据没有内容
for e in vault.audit_trail():
    print(f"  #{e['seq']} {e['action']} {e['ref']}")

# 5) 泄漏体检：只报位置，不回显内容
sample = "正常一行\n配置里混进了 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 这一段"
print("泄漏体检：", scan_text(sample))

print("概览：", vault.describe())
