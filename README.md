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

# 增量追加：只计算新文件的哈希，已记录的文件跳过(不读盘)
python metadata.py gen --append -m X:\manifest.tsv X:\data

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

## 增量维护清单（`--append`）

场景：目录里的文件分批增加（例如密文随空间逐步生成），不想每次都对整个目录重算哈希。

```bash
# 第 1 批：首次全量生成（不加 --append）
python metadata.py gen -m F:\cipher\checksums.tsv F:\cipher

# 第 2 批起：只算新增文件，已有条目原样保留
python metadata.py gen --append -m F:\cipher\checksums.tsv F:\cipher

# 校验仍是对整条清单全量校验，用法不变
python metadata.py verify -m F:\cipher\checksums.tsv
```

要点：

- `--append` 按**相对路径**判断"是否已有"：命中已有路径就跳过，**完全不读该文件**。
  所以已生成的密文不会再被读一遍，耗时只与新增量成正比。
- 目标既可以传目录，也可以传**具体文件**。传具体文件时行为相同：
  清单里已有这个路径就跳过（不核对内容），没有就追加一条。
- 清单不存在时 `--append` 等价于普通全量生成，不会报错。
- 追加时沿用清单里记录的算法（`-a` 与之冲突会被忽略并提示）；`created` 保留首次时间。
- **已有文件被改动不会被 `--append` 发现**——它只看路径新增。检测内容改动是 `verify` 的职责。
- 跨目录比对时，`gen` 与 `verify` 的 `--root` 必须一致，否则相对路径对不上。
- 如果文件被删除，`--append` 不会清理清单里的旧条目，需用不带 `--append` 的全量 `gen` 重建。

## 进度反馈

`gen` 默认输出实时进度，`-q` / `--quiet` 可完全静默：

```
扫描到 235 个文件，算法=sha256
清单将写入: F:\cipher_checksums.tsv
待哈希 235 个文件，共 18.7GB
[   1/ 235]   0.4% | 81.2MB/18.7GB | 45.2MB/s | ETA 7分02秒 | xxxxxx.bin
  |-bigfile.bin: 1.3GB/2.0GB (67%) 1.3GB/s     ← 单个大文件内部每秒刷新
[   2/ 235]   0.9% | ...
```

- 每个文件完成输出一行：序号/总数、百分比、已处理/总字节、当前速度、ETA、文件名。
- 单个大文件每 1 秒刷新一次内部百分比，同一行覆盖显示，不会看起来"卡住"。
- 总量在扫描阶段一次汇总；`--append` 时只统计真正需要哈希的新文件，跳过的不计入。
- ETA 按已读字节速度估算（密文文件大小差异大，按文件数估时不准）。

## 单文件更新：`--update-one` / `--upsert`

当你想针对**某一个**文件刷新校验值时用这个独立开关（与 `--append` 互不干扰）。
它必须有且只有一个文件参数：

```bash
# 已有记录 → 重新算哈希并核对
python metadata.py gen --update-one -m F:\cipher\checksums.tsv F:\securefs_cipher\xxxxxx
# 别名 --upsert 完全等价
python metadata.py gen --upsert -m F:\cipher\checksums.tsv F:\securefs_cipher\xxxxxx
```

三种结果：

| 情形 | 行为 | 输出前缀 |
| --- | --- | --- |
| 清单已有该文件，新哈希**相同** | 清单**完全不动**，不产生备份 | `UNCHANGED` |
| 清单已有该文件，新哈希**不同** | 先把旧清单复制为 `checksums.tsv.bak.<时间戳>`，再只改这一行 | `UPDATED` |
| 清单中**没有**该文件 | 追加一条新记录（等价于对单文件做 `--append`） | `ADDED` |

要点：

- **只有内容真变了才会备份**，重复运行不会产生一堆 `.bak` 文件。
- 备份是整份清单的快照（带 `shutil.copy2` 保留时间戳），可随时回滚。
- 沿用清单里的算法与 `created` 时间；清单不存在时按全量生成处理。
- 与 `--append` 同时给出时，**`--update-one` 优先**（因为它直接退出，不会走到追加逻辑）。
- 想核对而不改动清单，用 `verify` 而非本开关：
  `python metadata.py verify -m F:\cipher\checksums.tsv F:\securefs_cipher\xxxxxx`。

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
