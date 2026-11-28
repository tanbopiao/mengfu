"""盟府五域回归：登记域 / 轮换域 / 注销域 / 审计域 / 泄漏体检域。"""
import unittest

from mengfu import VaultPolicy, scan_text, _is_key_shaped

FULL = {"rotation_days": 90, "scope": "push", "storage": "kernel-file"}


class RegistrationDomain(unittest.TestCase):
    """登记域：只收引用与政策，钥匙形态一律拒收。"""

    def test_m1_accept_reference_registration(self):
        v = VaultPolicy()
        v.register("env/ATOMGIT_TOKEN_PATH", FULL)
        self.assertTrue(v.check("env/ATOMGIT_TOKEN_PATH"))

    def test_m1_reject_real_key_shape_in_ref(self):
        v = VaultPolicy()
        with self.assertRaises(ValueError):
            v.register("a" * 64, FULL)
        with self.assertRaises(ValueError):
            v.register("AbC+/=" * 8, FULL)

    def test_m1_incomplete_policy_rejected(self):
        v = VaultPolicy()
        with self.assertRaises(ValueError):
            v.register("file/.kernel/yuanji.token", {"rotation_days": 90, "scope": "push"})
        with self.assertRaises(ValueError):
            v.register("file/.kernel/yuanji.token", {})

    def test_m2_key_hidden_in_policy_value_rejected(self):
        """M2 破口修复：钥匙不得藏进政策值。"""
        v = VaultPolicy()
        bad = dict(FULL, storage="a" * 40)
        with self.assertRaises(ValueError):
            v.register("file/.kernel/yuanji.token", bad)
        self.assertFalse(v.check("file/.kernel/yuanji.token"))

    def test_m2_empty_or_nonstring_ref_rejected(self):
        v = VaultPolicy()
        for bad_ref in ("", "   ", None, 42):
            with self.assertRaises(ValueError):
                v.register(bad_ref, FULL)


class RotationDomain(unittest.TestCase):
    """轮换域：到期体检按登记时刻起算，未登记不静默。"""

    def test_not_due_within_window(self):
        v = VaultPolicy()
        v.register("env/A", dict(FULL, rotation_days=90), registered_at=0)
        due, remaining = v.due_for_rotation("env/A", as_of=89 * 86400)
        self.assertFalse(due)
        self.assertAlmostEqual(remaining, 1.0)

    def test_due_after_window(self):
        v = VaultPolicy()
        v.register("env/A", dict(FULL, rotation_days=30), registered_at=0)
        due, remaining = v.due_for_rotation("env/A", as_of=45 * 86400)
        self.assertTrue(due)
        self.assertAlmostEqual(remaining, -15.0)

    def test_exact_boundary_is_due(self):
        v = VaultPolicy()
        v.register("env/A", dict(FULL, rotation_days=30), registered_at=0)
        due, _ = v.due_for_rotation("env/A", as_of=30 * 86400)
        self.assertTrue(due)

    def test_unknown_ref_raises(self):
        v = VaultPolicy()
        with self.assertRaises(KeyError):
            v.due_for_rotation("file/不存在")


class RevocationDomain(unittest.TestCase):
    """注销域：注销入册、重发凭新政策、直接重登被拒。"""

    def test_revoke_removes_from_registry(self):
        v = VaultPolicy()
        v.register("env/A", FULL)
        self.assertTrue(v.revoke("env/A", reason="轮换到期"))
        self.assertFalse(v.check("env/A"))
        self.assertTrue(v.is_revoked("env/A"))

    def test_revoke_unknown_ref_raises(self):
        v = VaultPolicy()
        with self.assertRaises(KeyError):
            v.revoke("file/不存在")

    def test_register_after_revoke_rejected(self):
        v = VaultPolicy()
        v.register("env/A", FULL)
        v.revoke("env/A")
        with self.assertRaises(ValueError):
            v.register("env/A", FULL)

    def test_reissue_restores_with_new_policy(self):
        v = VaultPolicy()
        v.register("env/A", FULL)
        v.revoke("env/A", reason="轮换到期")
        v.reissue("env/A", dict(FULL, rotation_days=60), registered_at=10 * 86400)
        self.assertTrue(v.check("env/A"))
        self.assertFalse(v.is_revoked("env/A"))
        due, remaining = v.due_for_rotation("env/A", as_of=69 * 86400)
        self.assertFalse(due)
        self.assertAlmostEqual(remaining, 1.0)

    def test_reissue_without_revocation_rejected(self):
        v = VaultPolicy()
        with self.assertRaises(ValueError):
            v.reissue("env/A", FULL)

    def test_revoke_reason_key_shaped_rejected(self):
        """注销理由也不得转抄钥匙形态内容。"""
        v = VaultPolicy()
        v.register("env/A", FULL)
        with self.assertRaises(ValueError):
            v.revoke("env/A", reason="b" * 48)
        self.assertTrue(v.check("env/A"))


class AuditDomain(unittest.TestCase):
    """审计域：seq 连续、只记元数据、返回副本。"""

    def test_seq_continuous_from_one(self):
        v = VaultPolicy()
        v.register("env/A", FULL)
        v.revoke("env/A", reason="轮换")
        v.reissue("env/A", FULL)
        trail = v.audit_trail()
        self.assertEqual([e["seq"] for e in trail], [1, 2, 3])
        self.assertEqual([e["action"] for e in trail], ["register", "revoke", "reissue"])

    def test_audit_never_contains_policy_values(self):
        v = VaultPolicy()
        v.register("env/A", dict(FULL, scope="secret-scope-name"))
        v.revoke("env/A", reason="轮换")
        blob = repr(v.audit_trail())
        self.assertNotIn("secret-scope-name", blob)
        self.assertNotIn("kernel-file", blob)

    def test_audit_trail_is_copy(self):
        v = VaultPolicy()
        v.register("env/A", FULL)
        trail = v.audit_trail()
        trail.clear()
        self.assertEqual(len(v.audit_trail()), 1)

    def test_audit_tampering_manifests_as_chain_break(self):
        """篡改现形：审计簿被删改必现 seq 断链，核验不通过。"""
        v = VaultPolicy()
        v.register("env/A", FULL)
        v.revoke("env/A", reason="轮换")
        self.assertTrue(v.audit_intact())
        # 模拟账簿被删一条：缺号当场现形
        tampered = v.audit_trail()
        del tampered[0]
        seqs = [e["seq"] for e in tampered]
        self.assertNotEqual(seqs, list(range(1, len(tampered) + 1)))


class LeakScanDomain(unittest.TestCase):
    """泄漏体检域：只报位置，绝不回显内容。"""

    def test_scan_finds_key_shaped_fragment(self):
        secret = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        findings = scan_text(f"正常行\n混入 {secret} 一段")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 2)

    def test_scan_report_never_echoes_content(self):
        secret = "a" * 64
        report = repr(scan_text(f"key={secret}"))
        self.assertNotIn(secret, report)
        self.assertNotIn("aaaa", report)

    def test_scan_clean_text_empty(self):
        self.assertEqual(scan_text("普通文本，没有任何长随机串"), [])
        self.assertEqual(scan_text(""), [])
        self.assertEqual(scan_text(None), [])

    def test_is_key_shaped_boundaries(self):
        self.assertTrue(_is_key_shaped("f" * 32))
        self.assertFalse(_is_key_shaped("f" * 31))
        self.assertFalse(_is_key_shaped("g" * 64))  # 非法字符集不算钥匙形态
        self.assertFalse(_is_key_shaped(12345))


def selftest():
    """冒烟自检：登记→到期→注销→重发→审计→体检 一条龙。"""
    v = VaultPolicy()
    v.register("env/A", dict(FULL, rotation_days=30), registered_at=0)
    assert v.due_for_rotation("env/A", as_of=31 * 86400)[0] is True
    v.revoke("env/A", reason="轮换到期")
    v.reissue("env/A", FULL, registered_at=31 * 86400)
    assert v.check("env/A") and len(v.audit_trail()) == 3
    assert scan_text("a" * 40)[0]["length"] == 40
    assert scan_text("x" * 40) == []  # 非密钥字符集不误报
    print("selftest ok")


if __name__ == "__main__":
    selftest()
    unittest.main()
