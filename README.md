# 盟府 · 凭据治理规范（mengfu）

道统算子谱单算子仓：`mengfu` 及其全量用例。总谱（17 枚算子 + 总控进化 + MCP 门面）见 [daotong-ops 总仓](https://github.com/tanbopiao/daotong-ops)。

## 定名语义
- 道统出处：勋藏盟府，司盟之府
- 工程映射：密钥治理政策层，永不存真实钥匙

## 这是什么

一个纯标准库的凭据治理政策层：凭据只登记「引用名 + 治理政策」，钥匙本身永远不进册。提供轮换到期体检、注销重发、只追加的治理审计簿，以及只报位置不回显内容的泄漏体检。适合给「哪把钥匙该换了、谁动过政策、文本里有没有误藏密钥」出一本明白账。

## 道统映射

| 道统名 | 内核对象 | 职责 |
|--------|----------|------|
| 盟府 | `VaultPolicy` | 凭据只登记引用与政策，钥匙形态内容一律拒收 |
| 轮换 | `due_for_rotation` | 按登记时刻起算轮换期，到期即报，未登记不静默 |
| 注销重发 | `revoke / reissue` | 注销入册留痕，重发必须凭完整新政策重新起算 |
| 审计簿 | `audit_trail` | 只追加，seq 连续，只记动作元数据不记政策值 |
| 泄漏体检 | `scan_text` | 找出文本中疑似密钥片段，只报行/列/长度，绝不回显内容 |

## 快速开始

```python
from mengfu import VaultPolicy, scan_text

vault = VaultPolicy()
vault.register("env/ATOMGIT_TOKEN_PATH",
               {"rotation_days": 90, "scope": "push", "storage": "kernel-file"})

vault.due_for_rotation("env/ATOMGIT_TOKEN_PATH", as_of=89 * 86400)  # (False, 1.0)
vault.revoke("env/ATOMGIT_TOKEN_PATH", reason="轮换到期")
vault.reissue("env/ATOMGIT_TOKEN_PATH",
              {"rotation_days": 90, "scope": "push", "storage": "kernel-file"})

scan_text("配置里混入 aabb... 长随机串")  # 只报位置，不回显内容
```

命令行：

```bash
python tools/mengfu.py register --ref env/TOKEN_PATH --rotation-days 90 --scope push --storage kernel-file
python tools/mengfu.py rotation --ref env/TOKEN_PATH
python tools/mengfu.py revoke --ref env/TOKEN_PATH --reason 轮换到期
python tools/mengfu.py scan --file path/to/scan.py
python tools/mengfu.py audit
```

## 设计约定

- 纯标准库，无第三方依赖。
- 盟府永不存真实钥匙：引用名、政策值、注销理由凡形似密钥（长度≥32 的随机 hex/base64 串）一律拒收。
- 已注销的引用不接受直接登记，重发必须走 `reissue()` 凭完整新政策。
- 审计簿只追加、只含元数据；泄漏体检只报坐标不回显内容。

## 回归

`regression.md` 登记十二条回归铁律（登记契约、轮换契约、注销契约、审计契约、体检契约、工程契约）。运行：

```bash
python3 -m unittest discover -s . -p "test_*.py"
```

## 许可证

MIT Licensed
