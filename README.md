# bres / BOOTSTRAP / Hxv4 XP3 资源静态提取分析

本仓库存放 Kirikiri / XP3 游戏中一类 `bres://`、`BOOTSTRAP`、`Hxv4`、FilterManager 加密链路的分析文档和提取工具。当前推荐路线是纯静态恢复：不启动游戏、不附加调试器，直接从目标 EXE、PE Resources 和 XP3 包恢复 `drip_program.json`，再用它验证或提取资源。

动态 dump / 运行时抓取脚本仍保留在仓库中，主要用于对照旧流程或处理静态流程尚未覆盖的新样本；日常使用优先看静态流程。

已测试程序包括：`**的夜宴（Steam ver.）`，`****随想曲`，`*******与终结之花`，`*******妹妹的乡间生活（Steam ver.）`。如果在其他程序中出现问题，欢迎提交 issue 并向我提供样本进行适配。

## TL;DR

| 目标 | 入口 |
|------|------|
| 从零跑通静态恢复、验证、提取和后处理 | [docs/usage/TryItOut.md](docs/usage/TryItOut.md) |
| 看完整数据流和关键状态传递 | [Flowchart.md](Flowchart.md) |
| 理解纯静态 FilterManager 派生 | [docs/static/DeriveFilterManager_Static.md](docs/static/DeriveFilterManager_Static.md) |
| 适配另一款同类加密游戏 | [docs/static/Porting_Static_Flow.md](docs/static/Porting_Static_Flow.md) |
| 理解 Hxv4 / DripValue / FilterRuntimeState | [docs/core/Hxv4Ripped.md](docs/core/Hxv4Ripped.md) |
| 理解 `System.checkSignature` 和 `.sig` 文件校验 | [docs/core/FileSignatureCheck.md](docs/core/FileSignatureCheck.md) |
| 理解 XP3 容器和提取边界 | [docs/core/XP3Extract.md](docs/core/XP3Extract.md) |
| 处理 PSB/PIMG CG 合成 | [docs/usage/TryItOut.md#7-psbpimg-和-cg-合成工具](docs/usage/TryItOut.md#7-psbpimg-和-cg-合成工具) |

## 当前推荐流程


```powershell
python src\static_extract\static_xp3_recover.py `
  --exe path\to\game.exe `
  --work-dir Temp\static_recover `
  --debug

python src\common\xp3_inspect.py verify `
  path\to\main.xp3 path\to\scn.xp3 `
  --filter recovered `
  --drip-program Temp\static_recover\drip_program.json `
  --max-entries 20

python src\common\xp3_inspect.py extract-all `
  Temp\xp3_extract `
  path\to\scn.xp3 `
  --filter recovered `
  --drip-program Temp\static_recover\drip_program.json
```

`static_xp3_recover.py` 会完成：

1. 从目标 EXE 的 PE Resources 读取 `STARTUP.TJS`、`BOOTSTRAP`、可选 `PLUGIN` 和 `TEXT/127`。
2. 自动定位或读取 8192 字节 bres salt，并用 `STARTUP.TJS -> TJS2100\0` 校验。
3. 用 `SHA3-384(path_key_utf16le + salt) + ChaCha8` 解密 bres 资源。
4. 反编译或检查 `STARTUP.TJS`，提取 `_bootStrap("...")` 的脚本级 prefix。
5. 解密 `BOOTSTRAP`，跳过默认 8 字节头后 zlib 解压出随机 DLL。
6. 读取 DLL 配置表中的 `UNIQUE`、`WARNING` 等配置。
7. 调用 `tools\FilterManagerDerive` 离线派生 FilterManager/DripValue 状态。
8. 写出 `drip_program.json`，并可透传 `--verify` 或 `--extract-output` 直接验证/提取 XP3。

适配新样本时建议先做有限验证，不要直接对所有包做全量验证：

```powershell
python src\common\xp3_inspect.py verify `
  path\to\main.xp3 path\to\scn.xp3 `
  --filter recovered `
  --drip-program Temp\static_recover\drip_program.json `
  --max-entries 20
```

## 工具地图

| 工具 | 用途 | 典型命令 |
|------|------|----------|
| `src\static_extract\static_xp3_recover.py` | 静态恢复 bres 资源、BOOTSTRAP DLL 和 `drip_program.json` | `python src\static_extract\static_xp3_recover.py --exe game.exe --work-dir Temp\static_recover --debug` |
| `src\static_extract\recover_bres_salt.py` | 单独定位、扫描或验证 bres salt | `python src\static_extract\recover_bres_salt.py --exe game.exe --scan --out bres_salt.bin` |
| `src\static_extract\compute_resource_hash.py` | 计算 XP3 path/file hash，并可用 `manifest.jsonl` 精确查找输出文件和格式 | `python src\static_extract\compute_resource_hash.py --filename cglist.csv --manifest Temp\xp3_extract\manifest.jsonl` |
| `src\common\xp3_inspect.py` | XP3 摘要、查找、Hxv4 解析、验证、单文件提取、整包提取 | `python src\common\xp3_inspect.py extract-all outdir file.xp3 --filter recovered --drip-program drip_program.json` |
| `tools\scan_headers.py` | 对提取目录中的 `.bin` 做全量 magic/header 分类 | `python tools\scan_headers.py -i Temp\xp3_extract -o Temp\file_type_report.txt --layout flat` |
| `tools\psb_parser.py` | 检查 PSB/PIMG、导出嵌入图片、合成 CG PNG | `python tools\psb_parser.py compose-all entry.bin -o Temp\output\entry` |
| `tools\descramble_files.py` | 解扰 Kirikiri scrambled UTF-16LE 文本 | `python tools\descramble_files.py -i Temp\xp3_extract -o Temp\descrambled` |
| `tools\cglist_diff_map.py` | 用 `imagediffmap.csv` 解析 `cglist.csv` 的基础图和差分标签 | `python tools\cglist_diff_map.py cglist.csv imagediffmap.csv --json` |
| `src\common\tjs2_inspect.py` | 检查 `TJS2100` 字节码容器 | `python src\common\tjs2_inspect.py file.tjs` |
| `src\common\parse_dialogue.py` | 从已转换的 `.ks.json` 中导出对话文本 | `python src\common\parse_dialogue.py input_dir -o out_dir -f all` |

更完整的工具说明和参数组合见 [TryItOut 命令索引](docs/usage/TryItOut.md#10-命令索引)。

## 文档结构

```plain
Flowchart.md                              # 当前静态流程总图
docs/
├── usage/
│   └── TryItOut.md                       # 推荐操作手册和工具命令索引
├── static/
│   ├── DeriveFilterManager_Static.md     # 纯静态恢复闭环
│   └── Porting_Static_Flow.md            # 跨游戏适配流程
├── core/
│   ├── Hxv4Ripped.md                     # Hxv4 / DripValue / FilterRuntimeState 总览
│   ├── hxv4/                             # Hxv4 表、KDF、资源路径/hash、VM、filter 拆分文档
│   ├── XP3Extract.md                     # XP3 容器结构和提取行为
│   └── Reverse.md                        # 早期总体逆向记录
├── live_dump/
│   └── DeriveFilterManager_LiveDump.md   # 动态 dump 旧路线
└── diff/
    └── DllDiff.md                        # BOOTSTRAP DLL 配置差异
```

第三方工具说明：

- [tools/tjs2-decompiler/README.md](tools/tjs2-decompiler/README.md)
- [tools/tlg2png/README.md](tools/tlg2png/README.md)
- [tools/FilterManagerDerive/README.md](tools/FilterManagerDerive/README.md)

## 代码结构

```plain
src/
├── static_extract/
│   ├── static_xp3_recover.py       # 当前推荐的静态恢复主入口
│   ├── bres_bootstrap.py           # bres/BOOTSTRAP 解密和配置解析共用逻辑
│   ├── recover_bres_salt.py        # bres salt 定位、扫描、校验
│   └── compute_resource_hash.py    # path/file hash 和 manifest 精确查找
│
├── common/
│   ├── xp3_inspect.py              # XP3 摘要、Hxv4、验证、提取
│   ├── decrypt_bres_resource.py    # bres:// 解密旧辅助脚本
│   ├── tjs2_inspect.py             # TJS2100 字节码检查
│   ├── resource_hash.py            # XP3 资源哈希实现
│   ├── pe_image.py                 # PE section/resource 读取
│   └── parse_dialogue.py           # KAG/KS 对话导出
│
└── dynamic_capture/                # 运行时 dump / 旧路线辅助工具
    ├── capture_bootstrap_args.py
    ├── watch_random_plugin_dump.py
    ├── inspect_manager_dump.py
    ├── filter_manager_dump.py
    ├── minidump_reader.py
    └── minidump_process.py

tools/
├── FilterManagerDerive/            # x86 .NET 离线派生 FilterManager 状态
│   ├── Program.cs
│   └── FilterManagerDerive.csproj
├── tjs2-decompiler/                # TJS2 字节码反编译器
├── tlg2png/                        # TLG -> PNG 转换器
├── psb_parser.py                   # PSB/PIMG 检查、提取、合成
├── scan_headers.py                 # 提取结果全量 header 分类
├── descramble_files.py             # Kirikiri scrambled 文本解扰
└── cglist_diff_map.py              # CG 列表和差分映射解析
```

## 数据目录

```plain
data/
├── static_recover/                 # 已记录的静态恢复样例输出
└── live_dump/                      # 早期动态 dump 样例输出

sample/                             # XP3/Hxv4/TJS2 局部样本
Temp/                               # 推荐的本地实验输出目录，通常不作为源码资料引用
```

## 环境要求

- Windows + PowerShell。
- Python 3.9+。
- `pycryptodome`，用于 bres / Hxv4 / FilterManager 相关加密原语。
- Pillow，用于 `tools\psb_parser.py` 的 PNG 读取和 alpha 合成。
- .NET 8 x86 runtime 或 SDK，用于运行 `tools\FilterManagerDerive`。
- `tools\tlg2png\tlg2png.exe`，用于 TLG 图片转换。

安装 Python 依赖：

```powershell
pip install pycryptodome pillow
```

## 动态 Dump / 运行时抓取

动态路线已不再是默认用法。它适合在新样本静态流程失败时做对照，例如抓取 `System_bootStrap_callback` 参数、监控 `%TEMP%\krkr_...\<random>.dll`、或从 full-memory minidump 中恢复 FilterManager 状态。

相关文档和脚本：

- [docs/live_dump/DeriveFilterManager_LiveDump.md](docs/live_dump/DeriveFilterManager_LiveDump.md)
- [docs/core/Reverse.md](docs/core/Reverse.md)
- `src\dynamic_capture\capture_bootstrap_args.py`
- `src\dynamic_capture\watch_random_plugin_dump.py`
- `src\dynamic_capture\inspect_manager_dump.py`

## 第三方项目

- [crate-1556/tjs2-decompiler](https://github.com/crate-1556/tjs2-decompiler): Kirikiri / TJS2 字节码反编译器，本仓库在 `tools\tjs2-decompiler` 中保留辅助分析版本。
- [vn-tools/tlg2png](https://github.com/vn-tools/tlg2png): TLG 图片到 PNG 的转换工具，本仓库在 `tools\tlg2png` 中保留 Windows 可执行文件。

## AI 辅助创作、分析声明

本仓库的部分文档整理、代码注释、分析思路归纳和脚本实现过程可能使用 AI 工具辅助完成。AI 辅助内容均以人工审阅、验证和修订后的结果为准，不代表对相关游戏、引擎或第三方项目权利归属的声明或变更。

## 许可说明

本项目仅用于逆向工程研究和已合法购买资源的格式分析。仓库中的脚本和文档基于静态/动态分析独立编写，不包含游戏原始代码或资源文件。
