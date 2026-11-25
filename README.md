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

最常用的完整流程：**在 F: 生成清单（清单也放 F:，root 指向 F: 盘根），日后数据挪到 H: 后用同一份清单校验（root 换成 H: 盘根）**。

```bash
# 生成：清单 F:\cipher_checksums.tsv，数据 F:\securefs_cipher
# root 填 F:\ —— 清单里记的是相对盘根的路径 securefs_cipher\...
python D:\repos\metadata_tools_git\metadata.py gen -m F:\cipher_checksums.tsv --root F:\ F:\securefs_cipher

# 校验：数据已挪到 H:\securefs_cipher，root 换 H:\（层级不变，只换盘符）
python D:\repos\metadata_tools_git\metadata.py verify -m F:\cipher_checksums.tsv --root H:\ H:\securefs_cipher
```

其他示例：

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

## `--root` 是什么（最容易踩的坑）

**`--root` 是清单里相对路径的起点，不是数据目录本身。** 脚本拼文件路径时用的是：

```
真实路径 = <--root> + <清单里的相对路径>
```

清单里的相对路径长什么样，由 gen 时的 `--root` 决定；verify 要给出**同一层级**的起点，盘符或位置可以不同。

**怎么判断该填哪个目录**：看清单数据行的第一段，它对应真实文件系统里的哪一层，`--root` 就指向那一层的**上一级**。

| 清单里的相对路径 | 数据实际位置 | verify 该用的 `--root` |
| --- | --- | --- |
| `sub/a.bin` | `E:\source\sub\a.bin` | `E:\source` |
| `a.bin` | `F:\cipher\a.bin` | `F:\cipher` |
| `securefs_cipher/a.bin` | `H:\securefs_cipher\a.bin` | `H:\` |

**真实案例**（密文从 F: 挪到 H: 后校验）：清单里是 `securefs_cipher/.securefs.json`，第一段 `securefs_cipher` 是真实存在的目录，所以起点是盘根：

```bash
# 正确：H:\ + securefs_cipher\.securefs.json -> H:\securefs_cipher\.securefs.json
python metadata.py verify -m F:\cipher_checksums.tsv --root H:\

# 错误：H:\securefs_cipher + securefs_cipher\... -> 多拼一层，全部 MISSING
python metadata.py verify -m F:\cipher_checksums.tsv --root H:\securefs_cipher
```

**自查**：清单头部 `# base=...` 就是 gen 时的起点，跨盘时只换盘符、层级不变：

```bash
head -n 6 F:\cipher_checksums.tsv     # 看 # base= 那行
```

不写 `--root` 时，基准 = **清单文件所在目录**。所以清单放 `F:\`、gen 扫 `F:\cipher` 时，清单路径是 `cipher/...`，verify 在 F: 上不写 root 也能对上；数据换到 H: 后就必须显式写 `--root H:\`。

### 跨盘 / 跨目录比对的完整例子

两棵树结构相同、位置不同时（原始树 `E:\source` 与挂载成盘符的 ISO 内部树 `W:\mounted`）：

```bash
# gen：扫 E:\source，基准也设为 E:\source -> 清单路径形如 sub/a.bin（不含 source 这一层）
python metadata.py gen  -m X:\manifest.tsv --root E:\source E:\source

# verify：W:\mounted 与 E:\source 结构相同 -> 基准设为 W:\mounted
python metadata.py verify -m X:\manifest.tsv --root W:\mounted
```

注意这里 `--root` 恰好等于目标目录，是因为清单路径**不含**顶层目录名（`sub/a.bin`）。如果清单路径**含**顶层目录名（像上面的 `securefs_cipher/a.bin`），root 就必须退一级到父目录——这正是原来那段例子容易让人误解的地方。

## 增量续算与断点继续（默认行为）

**清单本身就是"已完成集合"**：里面的每一行都是算完并已落盘的记录。`gen` 默认就是增量——
清单存在就跳过已记录路径、只补算还没有的；清单不存在才全量生成。
不需要任何额外的断点标记文件。

```bash
# 第 1 次：清单不存在 -> 全量生成
python metadata.py gen -m F:\cipher\checksums.tsv F:\cipher

# 之后每次都是增量续算：已有跳过，只算新增（--append 可省略，写上也兼容）
python metadata.py gen -m F:\cipher\checksums.tsv F:\cipher

# 中途 Ctrl+C 中断：已算的每条都已落盘，直接重跑同一条命令即可接着算
#     不需要 --append，也不会重复已有条目

# 想强制从头全量重算（如文件已变更、要重建基线）：
python metadata.py gen --rebuild -m F:\cipher\checksums.tsv F:\cipher

# 校验仍是对整条清单全量校验，用法不变
python metadata.py verify -m F:\cipher\checksums.tsv
```

要点：

- **每条即落盘**：每算完一个文件立即 `flush + fsync` 写入清单，中断只损失当前正在算的那一个。
- 判断"是否已有"用**相对路径**：命中就跳过，**完全不读该文件**，耗时只与新增量成正比。
- 目标可传目录或具体文件；具体文件已记录就跳过、没有就追加一条。
- 续算时沿用清单里的算法与 `created` 时间（`-a` 冲突会被忽略并提示）；`base` 不一致会告警，请用相同 `--root`。
- **已有文件被改动不会被增量发现**——它只看路径新增。检测改动是 `verify` 的职责，改单条用 `--update-one`。
- 跨盘/跨目录比对时，`verify` 的 `--root` 与 gen 时的基准要**层级一致**（盘符可换），并且永远指向清单相对路径的起点，不是数据目录本身。详见上面的对照表。
- 文件被删除时清单旧条目不会自动清理，用 `--rebuild` 重建。

## 进度反馈

`gen` 和 `verify` 默认都输出实时进度，`-q` / `--quiet` 可完全静默（verify 下仍打印异常项）：

```
# gen
扫描到 235 个文件，算法=sha256
清单将写入: F:\cipher_checksums.tsv
待哈希 235 个文件，共 18.7GB
[   1/ 235]   0.4% | 81.2MB/18.7GB | 45.2MB/s | ETA 7分02秒 | xxxxxx.bin
  |-bigfile.bin: 1.3GB/2.0GB (67%) 1.3GB/s     ← 单个大文件内部每秒刷新
[   2/ 235]   0.9% | ...

# verify（结果在 stdout，进度在 stderr）
载入 238 条, 算法=sha256, 基准=H:\
待校验 238 条，共 18.7GB
[   1/ 238]   0.4% | 81.2MB/18.7GB | 45.2MB/s | ETA 7分02秒 | securefs_cipher/a.bin
  |-a.bin: 1.3GB/2.0GB (67%) 1.3GB/s           ← 单个大文件内部每秒刷新
```

- 每个文件完成输出一行：序号/总数、百分比、已处理/总字节、当前速度、ETA、文件名。
- 单个大文件每 1 秒刷新一次内部百分比，同一行覆盖显示，不会看起来"卡住"。
- 总量在处理前一次汇总；`verify` 传 target 时只统计命中的条目。
- ETA 按已读字节速度估算（密文文件大小差异大，按文件数估时不准）。
- `verify` 的结果行（`OK` / `MISSING` / `MISMATCH` / `ERROR`）仍走 stdout，进度走 stderr，方便重定向分离。

## 只校验部分文件（`verify` 传 target）

`verify` 后面可以直接跟**具体文件或目录**，只校验清单中命中的条目；没传则校验全部。
两种路径写法都支持：

```bash
# 清单相对路径（清单里记的是什么就写什么）
python metadata.py verify -m F:\cipher_checksums.tsv --root H:\ securefs_cipher\xxxxxx.bin

# 磁盘绝对路径（文件在盘上的实际位置）
python metadata.py verify -m F:\cipher_checksums.tsv --root H:\ H:\securefs_cipher\xxxxxx.bin

# 传目录：校验该目录下所有清单条目
python metadata.py verify -m F:\cipher_checksums.tsv --root H:\ H:\securefs_cipher

# 只核对不改动清单；--quiet 时 OK 不打印，只输出异常项
python metadata.py verify --quiet -m F:\cipher_checksums.tsv --root H:\ H:\securefs_cipher\xxxxxx.bin
```

- 目标没匹配到任何清单条目会明确报错并退出码 `2`，不会静默校验 0 条却显示成功。
- 传目录时按前缀匹配其下所有条目；传具体文件只校验这一个。
- 校验始终只读，不会改动清单；要改单条校验值用 `--update-one`。

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
- **`--root` 是清单相对路径的起点**（通常是数据目录的**父目录**，不是数据目录本身）；gen 与 verify 层级必须一致、盘符可不同。填错会拼出多一层的路径，表现为全部 `MISSING`。详见上面的对照表与案例。
- **年度校验先用 `--quick` 粗筛**，可疑项再全量校验，节省时间。
- 校验只负责**发现问题**，不负责保全数据——重要文件仍需多份副本。
