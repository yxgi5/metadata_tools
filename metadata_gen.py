#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
metadata_gen.py - 为目录/文件生成校验和清单 (manifest)

用途：
    对指定目录(递归)或文件计算哈希，输出一份清单文件，用于日后完整性校验。
    典型场景：冷备份盘(如本机 H: 18TB 企业盘)做完 chkdsk /r 后，扫描全盘点位，
    生成 checksum 清单；之后每年通电跑一次 metadata_verify.py，即可发现静默损坏。

相比“只记 sha256”的改进点：
    1. 路径用【相对路径】；基准默认=清单文件所在目录，可用 --root 指定为任意
       目录，从而支持跨盘/跨目录比对(如 E: 原始树 与 W: 挂载的 ISO 内部树，
       只要结构相同、盘符不同即可比对)。
    2. 全程 UTF-8，正确处理中文/特殊文件名(如 [DKGirl御女郎])。
    3. 大文件分块(4MB)读取，内存恒定，不爆内存。
    4. 单文件读取失败(坏扇区)只告警并跳过，不中断整轮扫描。
    5. 清单先写临时文件再原子改名，中途崩溃不会留下半截清单。
    6. 自动排除清单自身与工具脚本，避免自引用/抖动。
    7. 可选 --algorithm (sha256/sha1/md5/blake2b)，默认 sha256。
    8. 进度反馈(可 --quiet 关闭)。

用法见: metadata_gen.py --help
"""
import argparse
import hashlib
import os
import shutil
import sys
import time
from pathlib import Path

CHUNK = 4 * 1024 * 1024            # 4MB 分块
DEFAULT_MANIFEST = "checksums.tsv"
TOOL_NAMES = {"metadata_gen.py", "metadata_verify.py", "checksums.tsv"}


def _replace_with_retry(src, dst, tries=5):
    """Windows 下目标/源可能被杀软或索引器瞬时占用，重试几次再放弃。"""
    import time as _time
    last = None
    for i in range(tries):
        try:
            src.replace(dst)
            return
        except PermissionError as e:
            last = e
            if i < tries - 1:
                _time.sleep(0.5)
    raise last


def file_hash(path, algo, progress_cb=None):
    h = hashlib.new(algo)
    last_tick = time.time()
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
            if progress_cb and time.time() - last_tick >= 1.0:
                progress_cb(f.tell())
                last_tick = time.time()
    return h.hexdigest()


def _fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f}{unit}"
        n /= 1024


def _fmt_eta(sec):
    if sec < 60:
        return f"{sec:.0f}秒"
    if sec < 3600:
        return f"{int(sec // 60)}分{int(sec % 60):02d}秒"
    return f"{int(sec // 3600)}小时{int((sec % 3600) // 60):02d}分"


def iter_files(targets, follow_symlinks):
    files = []
    for t in targets:
        p = Path(t)
        if p.is_dir():
            for root, dirs, names in os.walk(p, followlinks=follow_symlinks):
                if not follow_symlinks:
                    # 不进入符号链接目录，避免循环
                    dirs[:] = [d for d in dirs
                               if not (Path(root) / d).is_symlink()]
                for n in names:
                    fp = Path(root) / n
                    if fp.is_symlink() and not follow_symlinks:
                        continue
                    if fp.is_file():
                        files.append(fp.resolve())
        elif p.is_file():
            if p.is_symlink() and not follow_symlinks:
                print(f"[WARN] 跳过符号链接文件: {t}", file=sys.stderr)
                continue
            files.append(p.resolve())
        else:
            print(f"[WARN] 跳过不存在的路径: {t}", file=sys.stderr)
    return files


def _load_manifest_raw(path):
    """读取已有清单 -> (entries, meta)。
    entries: relpath -> 原始数据行(不含换行)；meta: 头部 key->value。"""
    entries = {}
    meta = {}
    with open(path, encoding="utf-8") as mf:
        for line in mf:
            s = line.rstrip("\n")
            if s.startswith("#"):
                k, sep, v = s[1:].partition("=")
                if sep:
                    meta[k.strip()] = v.strip()
                continue
            if not s:
                continue
            p = s.split("\t")
            if len(p) == 4:
                entries[p[3]] = s
    return entries, meta


def _backup_manifest(path, reason):
    """变更清单前先复制一份带时间戳的备份；返回备份路径。"""
    stamp = time.strftime("%Y%m%d_%H%M%S")
    backup = path.with_name(f"{path.name}.bak.{stamp}")
    i = 1
    while backup.exists():
        backup = path.with_name(f"{path.name}.bak.{stamp}.{i}")
        i += 1
    shutil.copy2(path, backup)
    print(f"[BACKUP] {reason} -> {backup}", file=sys.stderr)
    return backup


def _write_manifest_lines(path, base_dir, algorithm, created, lines):
    """按已有行顺序重写清单（upsert 用），原子替换。"""
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as out:
        out.write("# disk-metadata-manifest v1\n")
        out.write(f"# algorithm={algorithm}\n")
        out.write(f"# created={created}\n")
        out.write(f"# base={base_dir}\n")
        out.write("# hash\tsize\tmtime\trelpath\n")
        for line in lines:
            out.write(line + "\n")
        out.flush()
        os.fsync(out.fileno())
    _replace_with_retry(tmp, path)


def _update_one(args, manifest_path, base_dir):
    """单文件 upsert：已有记录则核对，相同不动、不同则备份后更新；无记录则追加。"""
    targets = [t for t in args.targets if t]
    if len(targets) != 1:
        print("[ERROR] --update-one 要求恰好 1 个文件参数。",
              file=sys.stderr)
        sys.exit(2)
    p = Path(targets[0])
    if not p.is_file():
        print(f"[ERROR] --update-one 只接受单个文件: {targets[0]}",
              file=sys.stderr)
        sys.exit(2)
    target = p.resolve()
    try:
        rel = os.path.relpath(str(target), str(base_dir)).replace(os.sep, "/")
    except ValueError:
        print(f"[ERROR] 文件不在 --root 之下: {target}", file=sys.stderr)
        sys.exit(2)

    existing, meta = {}, {}
    if manifest_path.exists():
        existing, meta = _load_manifest_raw(manifest_path)
        old_algo = meta.get("algorithm")
        if old_algo and old_algo != args.algorithm:
            print(f"[INFO] 更新模式沿用清单算法 {old_algo}（忽略 -a {args.algorithm}）",
                  file=sys.stderr)
            args.algorithm = old_algo
        old_base = meta.get("base")
        if old_base and old_base != str(base_dir):
            print(f"[WARN] 清单 base={old_base} 与当前 base={base_dir} 不一致，"
                  f"相对路径可能对不上；请用相同 --root。", file=sys.stderr)

    try:
        st = target.stat()
        cur_hash = file_hash(target, args.algorithm)
    except Exception as e:
        print(f"[ERROR] 读取失败(可能坏扇区): {target} -> {e}", file=sys.stderr)
        sys.exit(1)
    new_line = f"{cur_hash}\t{st.st_size}\t{int(st.st_mtime)}\t{rel}"

    if rel in existing:
        old_line = existing[rel]
        old_hash = old_line.split("\t")[0]
        if cur_hash == old_hash:
            print(f"UNCHANGED\t{rel}\t与原校验一致（清单未改动）")
            sys.exit(0)
        _backup_manifest(manifest_path, f"校验变化: {rel}")
        lines = [new_line if v == old_line else v for v in existing.values()]
        print(f"UPDATED\t{rel}\t旧={old_hash[:16]}... 新={cur_hash[:16]}...")
    else:
        lines = list(existing.values()) + [new_line]
        print(f"ADDED\t{rel}\t清单原无记录，已追加")

    created = meta.get("created") or time.strftime("%Y-%m-%dT%H:%M:%S%z")
    try:
        _write_manifest_lines(manifest_path, base_dir, args.algorithm,
                              created, lines)
    except Exception as e:
        print(f"[ERROR] 写清单失败: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"[INFO] 清单已更新: {manifest_path}", file=sys.stderr)
    sys.exit(0)


def main():
    ap = argparse.ArgumentParser(
        prog="metadata_gen.py",
        description="为目录/文件生成校验和清单(manifest)。默认扫描当前目录，"
                    "清单默认写到与脚本同目录的 checksums.tsv。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  metadata_gen.py                 # 扫当前目录, 清单放脚本同目录\n"
               "  metadata_gen.py D:\\photos       # 扫指定目录\n"
               "  metadata_gen.py a.iso b.iso     # 只记这两个文件\n"
               "  metadata_gen.py -m X:\\my.tsv    # 指定清单位置\n"
               "  metadata_gen.py -a blake2b      # 用更快的 blake2b\n",
    )
    ap.add_argument("targets", nargs="*", default=["."],
                    help="要扫描的文件或目录(可多个)，默认当前目录")
    ap.add_argument("--manifest", "-m", default=None,
                    help="清单输出路径，默认: 脚本同目录/checksums.tsv")
    ap.add_argument("--algorithm", "-a", default="sha256",
                    choices=["sha256", "sha1", "md5", "blake2b"],
                    help="哈希算法 (默认 sha256)")
    ap.add_argument("--follow-symlinks", action="store_true",
                    help="跟随符号链接(默认不跟随，避免循环)")
    ap.add_argument("--root", default=None,
                    help="相对路径基准目录。gen 与 verify 必须用同一个 root "
                         "才能跨盘/跨目录比对(例如 E: 原始树 与 W: 挂载的 ISO "
                         "内部树结构相同但盘符不同)。默认=清单所在目录。")
    ap.add_argument("--append", action="store_true",
                    help="显式指定增量模式（默认已是增量，此开关为兼容旧习惯保留）："
                         "已记录路径跳过(不读盘)，只算新增。")
    ap.add_argument("--rebuild", action="store_true",
                    help="强制全量重建清单：忽略已有记录，从头重算并覆盖。"
                         "用于文件已变更、想重新取基线时。")
    ap.add_argument("--update-one", "--upsert", dest="update_one",
                    action="store_true",
                    help="单文件更新模式：已有记录则核对哈希——相同则清单不变并提示，"
                         "不同则先备份原清单再更新；无记录则追加。"
                         "需恰好一个文件参数；与 --append 同用时本模式优先。")
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="关闭进度输出")
    args = ap.parse_args()

    script_path = Path(__file__).resolve()
    script_dir = script_path.parent
    manifest_path = (Path(args.manifest).resolve()
                     if args.manifest else script_dir / DEFAULT_MANIFEST)
    base_dir = (Path(args.root).resolve() if args.root
                else manifest_path.parent)   # 相对路径基准(可用 --root 覆盖)

    # 单文件 upsert：独立开关 --update-one；与 --append 语义完全分开
    if args.update_one:
        _update_one(args, manifest_path, base_dir)

    # 清单本身即进度：已记录路径跳过，只补算还没记录的。
    # 默认增量续算；--rebuild 强制全量重建。--append 保留为显式别名。
    rebuild = args.rebuild
    appending = manifest_path.exists() and not rebuild
    existing = {}       # relpath -> 原始整行
    meta = {}
    if appending:
        existing, meta = _load_manifest_raw(manifest_path)
        old_algo = meta.get("algorithm")
        if old_algo and old_algo != args.algorithm:
            print(f"[INFO] 沿用清单算法 {old_algo}（忽略 -a {args.algorithm}）",
                  file=sys.stderr)
            args.algorithm = old_algo
        old_base = meta.get("base")
        if old_base and old_base != str(base_dir):
            print(f"[WARN] 清单 base={old_base} 与当前 base={base_dir} 不一致，"
                  f"相对路径可能对不上；请用相同 --root。", file=sys.stderr)
        print(f"[INFO] 增量续算：已有 {len(existing)} 条，仅计算新增文件。",
              file=sys.stderr)
    else:
        print(f"[INFO] {'全量重建' if rebuild else '全量生成'}: {manifest_path}",
              file=sys.stderr)

    files = iter_files(args.targets, args.follow_symlinks)
    # 排除清单自身、工具脚本
    exclude = {manifest_path, script_path}
    files = [f for f in files
             if f not in exclude and f.name not in TOOL_NAMES]
    files.sort(key=lambda p: str(p).lower())

    if not args.quiet:
        print(f"扫描到 {len(files)} 个文件，算法={args.algorithm}"
              f"{'（增量追加）' if appending else ''}", file=sys.stderr)
        print(f"清单将写入: {manifest_path}", file=sys.stderr)

    # 预先统计本次真正需要哈希的文件数与总字节数，用于百分比和 ETA
    target_count = 0
    grand_total = 0
    if not args.quiet:
        for pf in files:
            try:
                rel_p = os.path.relpath(str(pf), str(base_dir)).replace(os.sep, "/")
                if appending and rel_p in existing:
                    continue
                grand_total += pf.stat().st_size
                target_count += 1
            except Exception:
                pass
        print(f"待哈希 {target_count} 个文件，共 {_fmt_bytes(grand_total)}",
              file=sys.stderr)

    # 逐条落盘：每算完一个文件立即 flush+fsync，中断也不丢已完成的记录。
    # 清单里已有的行就是"已完成集合"，无需额外标记。
    count = 0
    skipped = 0
    total_bytes = 0
    read_errors = 0
    t0 = time.time()
    progress_dirty = [False]   # 大文件内部进度是否已写过（决定是否需要清行）

    try:
        if appending:
            out = open(manifest_path, "a", encoding="utf-8", newline="\n")
            # 续写前确认已有内容以换行结尾，避免半截行粘连
            with open(manifest_path, "rb+") as chk:
                chk.seek(0, os.SEEK_END)
                if chk.tell() > 0:
                    chk.seek(-1, os.SEEK_END)
                    if chk.read(1) != b"\n":
                        chk.write(b"\n")
                        chk.flush()
                        os.fsync(chk.fileno())
        else:
            out = open(manifest_path, "w", encoding="utf-8", newline="\n")
            out.write("# disk-metadata-manifest v1\n")
            out.write(f"# algorithm={args.algorithm}\n")
            out.write(f"# created={time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n")
            out.write(f"# base={base_dir}\n")
            out.write("# hash\tsize\tmtime\trelpath\n")
            out.flush()
            os.fsync(out.fileno())

        with out:
            for f in files:
                try:
                    st = f.stat()
                    try:
                        rel = os.path.relpath(str(f), str(base_dir)).replace(os.sep, "/")
                    except ValueError:
                        print(f"[WARN] 跳过: 不在 --root 之下: {f}",
                              file=sys.stderr)
                        continue
                    if appending and rel in existing:
                        skipped += 1
                        continue
                    if rel.startswith(".."):
                        print(f"[WARN] 路径在清单基准之外(将含 ..): {rel}",
                              file=sys.stderr)

                    def _cb(done, _f=f, _st=st):
                        progress_dirty[0] = True
                        el2 = time.time() - t0
                        sp2 = (total_bytes + done) / el2 if el2 > 0 else 0
                        pct2 = done / _st.st_size * 100 if _st.st_size else 0
                        sys.stderr.write(
                            f"\r  |-{_f.name}: {_fmt_bytes(done)}"
                            f"/{_fmt_bytes(_st.st_size)} ({pct2:.0f}%) "
                            f"{_fmt_bytes(sp2)}/s"
                        )
                        sys.stderr.flush()

                    h = file_hash(f, args.algorithm,
                                  progress_cb=_cb if not args.quiet else None)
                    out.write(f"{h}\t{st.st_size}\t{int(st.st_mtime)}\t{rel}\n")
                    out.flush()
                    os.fsync(out.fileno())
                    existing[rel] = True   # 本轮内也去重，防同路径重复
                    count += 1
                    total_bytes += st.st_size
                except Exception as e:
                    if not args.quiet and progress_dirty[0]:
                        sys.stderr.write("\r" + " " * 100 + "\r")
                        progress_dirty[0] = False
                    print(f"[ERROR] 读取失败(可能坏扇区): {f} -> {e}",
                          file=sys.stderr)
                    read_errors += 1
                if not args.quiet:
                    if progress_dirty[0]:
                        sys.stderr.write("\r" + " " * 100 + "\r")
                        progress_dirty[0] = False
                    el = time.time() - t0
                    speed = total_bytes / el if el > 0 else 0
                    remain = max(0, grand_total - total_bytes)
                    eta = remain / speed if speed > 0 else 0
                    pct = count / target_count * 100 if target_count else 100.0
                    line = (f"[{count:4d}/{target_count:4d}] {pct:5.1f}% | "
                            f"{_fmt_bytes(total_bytes)}/{_fmt_bytes(grand_total)} | "
                            f"{_fmt_bytes(speed)}/s | ETA {_fmt_eta(eta)} | {f.name}")
                    sys.stderr.write(line + "\n")
                    sys.stderr.flush()
    except KeyboardInterrupt:
        if not args.quiet and progress_dirty[0]:
            sys.stderr.write("\r" + " " * 100 + "\r")
        print(f"\n[ABORT] 已中断：本次新增 {count} 条已逐条落盘，清单保留。",
              file=sys.stderr)
        print(f"        重新运行同一命令即可接着算（清单里已有的会跳过）。",
              file=sys.stderr)
        sys.exit(130)

    if not args.quiet:
        msg = f"完成: 新增 {count} 文件"
        if appending:
            msg += f"，跳过 {skipped} 个已有"
        msg += f", {_fmt_bytes(total_bytes)} -> {manifest_path}"
        print(msg, file=sys.stderr)
    if read_errors:
        print(f"[SUMMARY] {read_errors} 个文件读取失败(见上)，"
              f"已从清单排除，请排查坏扇区。", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
