#!/usr/bin/env python3
"""盟府 CLI：凭据治理政策层的命令行入口。

状态落在一个 JSON 政策册（默认 ./mengfu_state.json），
册内只有引用名、政策字段与注销理由，结构上放不进钥匙。

用法：
  python tools/mengfu.py register --ref env/TOKEN_PATH --rotation-days 90 --scope push --storage kernel-file
  python tools/mengfu.py check --ref env/TOKEN_PATH
  python tools/mengfu.py rotation --ref env/TOKEN_PATH
  python tools/mengfu.py revoke --ref env/TOKEN_PATH --reason 轮换到期
  python tools/mengfu.py reissue --ref env/TOKEN_PATH --rotation-days 90 --scope push --storage kernel-file
  python tools/mengfu.py list
  python tools/mengfu.py audit
  python tools/mengfu.py scan --file path/to/scan.py
  python tools/mengfu.py scan --text '粘贴待检文本'
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mengfu import VaultPolicy, scan_text


def load_state(path):
    vault = VaultPolicy()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for item in data.get("registered", []):
            vault.register(item["ref"], item["policy"], registered_at=item.get("registered_at"))
        for item in data.get("revoked", []):
            vault.revoke(item["ref"], reason=item.get("reason", ""))
    return vault


def save_state(path, vault):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vault.export_state(), f, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser(description="盟府 · 凭据治理政策层 CLI")
    parser.add_argument("--state", default="mengfu_state.json", help="政策册文件路径")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def policy_args(p):
        p.add_argument("--ref", required=True)
        p.add_argument("--rotation-days", type=int, required=True)
        p.add_argument("--scope", required=True)
        p.add_argument("--storage", required=True)

    policy_args(sub.add_parser("register", help="登记引用与政策"))
    policy_args(sub.add_parser("reissue", help="注销后凭新政策重发"))

    for name, help_text in (("check", "校验引用是否在册"), ("rotation", "轮换体检")):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("--ref", required=True)

    p = sub.add_parser("revoke", help="注销引用")
    p.add_argument("--ref", required=True)
    p.add_argument("--reason", default="")

    sub.add_parser("list", help="列出在册引用")
    sub.add_parser("audit", help="回看治理审计簿")

    p = sub.add_parser("scan", help="泄漏体检：只报位置不回显内容")
    p.add_argument("--file")
    p.add_argument("--text")

    args = parser.parse_args()
    vault = load_state(args.state)

    if args.cmd in ("register", "reissue"):
        policy = {"rotation_days": args.rotation_days, "scope": args.scope, "storage": args.storage}
        if args.cmd == "register":
            vault.register(args.ref, policy)
        else:
            vault.reissue(args.ref, policy)
        save_state(args.state, vault)
        print(f"已{'登记' if args.cmd == 'register' else '重发'}：{args.ref}")
    elif args.cmd == "check":
        print("在册" if vault.check(args.ref) else "不在册或已注销")
    elif args.cmd == "rotation":
        due, remaining = vault.due_for_rotation(args.ref)
        print(f"到期={due}，剩余 {remaining:.1f} 天")
    elif args.cmd == "revoke":
        vault.revoke(args.ref, reason=args.reason)
        save_state(args.state, vault)
        print(f"已注销：{args.ref}")
    elif args.cmd == "list":
        for ref in vault.list_refs():
            print(ref)
    elif args.cmd == "audit":
        for e in vault.audit_trail():
            print(f"#{e['seq']} {e['action']} {e['ref']} detail={e['detail']}")
    elif args.cmd == "scan":
        if args.file:
            with open(args.file, encoding="utf-8") as f:
                text = f.read()
        elif args.text is not None:
            text = args.text
        else:
            parser.error("scan 需要 --file 或 --text")
        findings = scan_text(text)
        if not findings:
            print("未发现疑似密钥片段")
        for item in findings:
            print(f"行 {item['line']} 列 {item['col']} 长度 {item['length']}（内容不回显）")


if __name__ == "__main__":
    main()
