# metadata_tools

磁盘文件校验和清单（manifest）工具：为目录/文件生成哈希清单，日后据此校验完整性，发现**静默损坏、内容被改、文件丢失、坏扇区读取失败**。

典型场景：冷备份盘做完检查后生成一次清单，每隔一段时间（如每年）通电重跑校验，即可发现长期静置导致的位衰减（bit rot）。

纯 Python 标准库，无需安装第三方依赖，Windows / Linux / macOS 通用。

## 三个脚本

| 脚本 | 作用 |
| --- | --- |
| `metadata_gen.py` | 单独生成清单 |
| `metadata_verify.py` | 单独校验清单 |
| `metadata.py` | 二合一版，用 `gen` / `verify` 子命令调用上面两个功能 |

三者功能等价，按需选用。推荐日常用 `metadata.py`（一个文件好拿），需要拆分流程时用前两个。

## 快速开始

```bash
# 扫描当前目录，清单写到脚本同目录的 checksums.tsv
python metadata.py gen

# 校验（用脚本同目录的 checksums.tsv）
python metadata.py verify

# 等价的两文件写法
python metadata_gen.py
python metadata_verify.py
```

## 常用示例

```bash
# 扫描指定目录 / 指定多个文件
python metadata.py gen D:\photos
python metadata.py gen a.iso b.iso

# 指定清单位置
python metadata.py gen -m X:\my.tsv
python metadata.py verify -m X:\my.tsv

# 换算法（sha256 / sha1 / md5 / blake2b，默认 sha256）
python metadata.py gen -a blake2b

# 快速粗筛：只比 size + mtime，不重算哈希（适合大量文件年度初筛）
python metadata.py verify --quick

# 只校验清单中的部分路径
python metadata.py verify D:\photos\subdir

# 额外报告磁盘上存在、但清单里没有的文件
python metadata.py verify --report-extra

# 安静模式：只输出异常项
python metadata.py gen -q
python metadata.py verify -q
```

完整参数见 `python metadata.py gen --help`、`python metadata.py verify --help`。

## 跨盘 / 跨目录比对（`--root`）

清单里记录的是**相对路径**，基准默认等于清单所在目录。若要对比两棵结构相同、位置不同的目录树（例如原始盘 `E:` 与挂载成盘符的 ISO 内部树 `W:`），生成和校验时都要用同一个 `--root`：

```bash
python metadata.py gen  -m X:\manifest.tsv --root E:\source E:\source
python metadata.py verify -m X:\manifest.tsv --root W:\mounted
```

`--root` 可以指向任意目录，使清单与实际数据分离存放。

## 清单格式

制表符分隔的 TSV，头部 `#` 注释行记录算法、时间、基准目录：

```
# disk-metadata-manifest v1
# algorithm=sha256
# created=2026-11-17T10:42:53+0800
# base=E:\source
# hash\tsize\tmtime\trelpath
<hex hash>\t<bytes>\t<unix mtime>\t<relative/path>
```

## 行为与退出码

- 大文件按 4MB 分块读取，内存占用恒定。
- 单个文件读取失败（如坏扇区）只告警并跳过，**不会中断整轮扫描**，也不会把错误数据写进清单。
- 清单先写临时文件再原子改名，中途崩溃不会留下半截清单。
- 自动排除清单自身和工具脚本，避免自引用。
- 校验退出码：`0` = 全部通过；`1` = 发现 MISMATCH / MISSING / ERROR；`2` = 用法或清单错误。

校验输出状态：

| 状态 | 含义 |
| --- | --- |
| `OK` | 完全一致 |
| `CHANGED` | `--quick` 模式下 size 或 mtime 变了 |
| `MISMATCH` | 内容（哈希或大小）不一致，可能损坏或被改 |
| `MISSING` | 清单中有、磁盘上没了 |
| `ERROR` | 读取失败（可能坏扇区），明确报错 |
| `EXTRA` | `--report-extra` 下磁盘多出的文件 |

## 使用建议

- **清单和数据分开放**：清单存到另一块盘或云端，避免和数据一起丢失。
- ** `--root` 前后一致**：gen 与 verify 必须用同一个基准，否则相对路径对不上。
- **年度校验先用 `--quick` 粗筛**，可疑项再全量校验，节省时间。
- 校验只负责**发现问题**，不负责保全数据——重要文件仍需多份副本。
