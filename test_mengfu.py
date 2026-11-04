import unittest
from mengfu import VaultPolicy

class T(unittest.TestCase):
    def test_accept_reference_registration(self):
        v = VaultPolicy()
        v.register("env/ATOMGIT_TOKEN_PATH", {"rotation_days": 90, "scope": "push", "storage": "kernel-file"})
        self.assertTrue(v.check("env/ATOMGIT_TOKEN_PATH"))

    def test_reject_real_key_shape(self):
        v = VaultPolicy()
        with self.assertRaises(ValueError):
            v.register("a" * 64, {"rotation_days": 90, "scope": "push", "storage": "kernel-file"})
        with self.assertRaises(ValueError):
            v.register("AbC+/=" * 8, {"rotation_days": 90, "scope": "push", "storage": "kernel-file"})

    def test_incomplete_policy_rejected(self):
        v = VaultPolicy()
        with self.assertRaises(ValueError):
            v.register("file/.kernel/yuanji.token", {"rotation_days": 90, "scope": "push"})
        with self.assertRaises(ValueError):
            v.register("file/.kernel/yuanji.token", {})

    def test_list_refs_never_leaks_values(self):
        v = VaultPolicy()
        v.register("file/.kernel/yuanji.token", {"rotation_days": 90, "scope": "push", "storage": "kernel-file"})
        refs = v.list_refs()
        self.assertEqual(refs, ["file/.kernel/yuanji.token"])
        # 清单里绝不能出现政策值或任何疑似密钥内容
        self.assertNotIn("rotation_days", str(refs))

    def test_check_unregistered_false(self):
        v = VaultPolicy()
        self.assertFalse(v.check("file/不存在"))

if __name__ == "__main__":
    unittest.main()
