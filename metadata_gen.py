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


def file_hash(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


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
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="关闭进度输出")
    args = ap.parse_args()

    script_path = Path(__file__).resolve()
    script_dir = script_path.parent
    manifest_path = (Path(args.manifest).resolve()
                     if args.manifest else script_dir / DEFAULT_MANIFEST)
    base_dir = (Path(args.root).resolve() if args.root
                else manifest_path.parent)   # 相对路径基准(可用 --root 覆盖)

    files = iter_files(args.targets, args.follow_symlinks)
    # 排除清单自身、工具脚本
    exclude = {manifest_path, script_path}
    files = [f for f in files
             if f not in exclude and f.name not in TOOL_NAMES]
    files.sort(key=lambda p: str(p).lower())

    if not args.quiet:
        print(f"扫描到 {len(files)} 个文件，算法={args.algorithm}",
              file=sys.stderr)
        print(f"清单将写入: {manifest_path}", file=sys.stderr)

    tmp = manifest_path.with_name(manifest_path.name + ".tmp")
    count = 0
    total_bytes = 0
    read_errors = 0
    t0 = time.time()
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as out:
            out.write("# disk-metadata-manifest v1\n")
            out.write(f"# algorithm={args.algorithm}\n")
            out.write(f"# created={time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n")
            out.write(f"# base={base_dir}\n")
            out.write("# hash\tsize\tmtime\trelpath\n")
            for f in files:
                try:
                    st = f.stat()
                    h = file_hash(f, args.algorithm)
                    try:
                        rel = os.path.relpath(str(f), str(base_dir)).replace(os.sep, "/")
                    except ValueError:
                        print(f"[WARN] 跳过: 不在 --root 之下: {f}",
                              file=sys.stderr)
                        continue
                    if rel.startswith(".."):
                        print(f"[WARN] 路径在清单基准之外(将含 ..): {rel}",
                              file=sys.stderr)
                    out.write(f"{h}\t{st.st_size}\t{int(st.st_mtime)}\t{rel}\n")
                    count += 1
                    total_bytes += st.st_size
                except Exception as e:
                    print(f"[ERROR] 读取失败(可能坏扇区): {f} -> {e}",
                          file=sys.stderr)
                    read_errors += 1
                if not args.quiet and count % 500 == 0:
                    el = time.time() - t0
                    print(f"  {count} 文件 / {total_bytes/1e9:.1f} GB "
                          f"/ {el:.0f}s ...", file=sys.stderr)
            out.flush()
            os.fsync(out.fileno())
        _replace_with_retry(tmp, manifest_path)  # 关闭句柄后再原子改名
    except KeyboardInterrupt:
        if tmp.exists():
            tmp.unlink()
        print("\n[ABORT] 已中断，临时文件已清理。", file=sys.stderr)
        sys.exit(130)

    if not args.quiet:
        print(f"完成: {count} 文件, {total_bytes/1e9:.2f} GB -> {manifest_path}",
              file=sys.stderr)
    if read_errors:
        print(f"[SUMMARY] {read_errors} 个文件读取失败(见上)，"
              f"已从清单排除，请排查坏扇区。", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
