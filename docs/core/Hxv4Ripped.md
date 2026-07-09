# Hxv4 加密体系总览

本文档是 Hxv4 / FilterManager / DripValue / stream filter 相关文档的总入口。原先集中在本文中的长篇分析已按加密链路拆分到 `docs/core/hxv4/` 下，本文只保留整体结构、阅读路径和关键实现入口。

这套保护并不是单一算法，而是由几层状态共同完成：

```plain
XP3 index
  -> Hxv4 descriptor
  -> XChaCha20-Poly1305 解密 Hxv4 payload
  -> zlib 解压资源映射表
  -> pathHash / fileHash 命中 record
  -> record.key + open_flag
  -> DripValue VM 派生 48-byte filter seed state
  -> FilterRuntimeState 对 XP3 entry 明文前的 buffer 做 stream XOR
  -> Adler32 校验
```

`drip_program.json` 保存了两层材料：

| 层级 | JSON 字段 | 用途 |
|------|-----------|------|
| Hxv4 payload 解密 | `hxv4_key`, `hxv4_nonce0`, `hxv4_nonce1` | 打开 XP3 index 中的 Hxv4 映射表 |
| Stream filter 派生 | `holder_words`, `context_u32`, `lanes` | 复现 DripValue VM，并为每条资源 record 派生实际过滤状态 |

## 阅读入口

| 问题 | 文档 |
|------|------|
| Hxv4 chunk 在 XP3 index 里是什么格式，payload 如何解密 | [hxv4/01-hxv4-table.md](hxv4/01-hxv4-table.md) |
| `hxv4_key`、nonce、DripValue 初始状态如何从 BOOTSTRAP DLL 派生 | [hxv4/02-bootstrap-kdf.md](hxv4/02-bootstrap-kdf.md) |
| 逻辑资源名如何变成 `domain_hash` / `file_hash` 并命中 Hxv4 record | [hxv4/03-resource-hash.md](hxv4/03-resource-hash.md) |
| DripValue VM 的 lane、opcode、`get64_from_u32()` 如何工作 | [hxv4/04-dripvalue-vm.md](hxv4/04-dripvalue-vm.md) |
| `record.key` 如何转成 48-byte seed state | [hxv4/05-filter-state.md](hxv4/05-filter-state.md) |
| 48-byte seed state 如何驱动实际 stream XOR | [hxv4/06-stream-filter.md](hxv4/06-stream-filter.md) |
| FilterManager 运行时对象和 `drip_program.json` 字段如何对应 | [hxv4/07-filter-manager-runtime.md](hxv4/07-filter-manager-runtime.md) |
| 运行时 stream read 调用链如何挂载 filter | [hxv4/08-runtime-read-path.md](hxv4/08-runtime-read-path.md) |
| 已验证样本中的 key/nonce 常量 | [hxv4/09-sample-constants.md](hxv4/09-sample-constants.md) |
| 全包验证结果 | [hxv4/10-validation-results.md](hxv4/10-validation-results.md) |

## 相关主线文档

- [Flowchart.md](../../Flowchart.md)：当前静态恢复和 XP3 解密总流程。
- [docs/static/DeriveFilterManager_Static.md](../static/DeriveFilterManager_Static.md)：不启动游戏时如何从 EXE/BOOTSTRAP DLL 静态派生 `drip_program.json`。
- [docs/static/Porting_Static_Flow.md](../static/Porting_Static_Flow.md)：如何把静态流程迁移到同一类加密的其他游戏。
- [docs/core/XP3Extract.md](XP3Extract.md)：XP3 容器、index、segment、Adler32 校验和提取边界。
- [docs/core/FileSignatureCheck.md](FileSignatureCheck.md)：`System.checkSignature`、`.sig` 文件、`extrasig` 和 BOOTSTRAP DLL 内 RSA-PSS/SHA256 校验流程。
- [docs/core/hxv4/03-resource-hash.md](hxv4/03-resource-hash.md)：主程序与 Bootstrap DLL 之间的资源路径、扩展名补全和 Hxv4 查找关系。

## 关键实现入口

| 实现 | 位置 | 作用 |
|------|------|------|
| Hxv4 payload 解密 | `src/common/xp3_inspect.py::decrypt_hxv4_payload` | 使用 `hxv4_key` 和 `hxv4_nonce[flags & 1]` 解密 payload |
| Hxv4 table 解析 | `src/common/xp3_inspect.py::parse_hxv4_table` | zlib 解压并解析 record |
| entry/filter 映射 | `src/common/xp3_inspect.py::build_filter_state_map` | 从 Hxv4 record 生成每个 entry 的 recovered filter |
| DripValue VM | `src/common/xp3_inspect.py::DripProgram` | 离线复现 lane VM 和 `get64_from_u32()` |
| stream filter | `src/common/xp3_inspect.py::FilterRuntimeState` | 对解压后的 entry buffer 应用 XOR 过滤 |
| 静态派生 | `src/static_extract/static_xp3_recover.py` | 从目标 EXE 和 BOOTSTRAP DLL 生成 `drip_program.json` |
| 离线 DLL 派生器 | `tools/FilterManagerDerive/Program.cs` | 加载 BOOTSTRAP DLL 并导出 FilterManager 状态 |

## 常见误区

- `Hxv4 descriptor.flags & 1` 才是选择 nonce 和构建 filter state 的 `open_flag`；不要使用 `record.filter_flag & 1`。
- `hxv4_key` / `hxv4_nonce*` 只负责打开映射表，不能直接解密资源内容。
- `record.key` 不是 XOR key；它必须先经过 DripValue VM 派生成 48-byte seed state。
- `scan_headers.py` 只做提取结果的批量 header 分类；按 manifest 精确查找资源输出应使用 `compute_resource_hash.py`。
