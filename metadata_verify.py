#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
metadata_verify.py - 依据 metadata_gen.py 生成的清单校验文件完整性

用途：
    重新计算(或快速比对)磁盘文件的哈希/尺寸/时间，与清单比对，输出:
        OK            完全一致
        MISMATCH      内容(hash 或 size)不一致 -> 可能损坏/被改
        MISSING       清单中有、磁盘上没了
        ERROR         读取失败(坏扇区) -> 明确报错，绝不吐出错误数据
    并支持 --report-extra 报告磁盘上存在但清单没有的文件。

设计要点：
    1. 路径相对【基准目录】解析；基准默认=清单所在目录，可用 --root 指定为
       目标树的结构根，从而跨盘/跨目录比对(gen/verify 须用同一 --root)。
    2. 单文件异常不中断整轮。
    3. 退出码: 0=全部通过; 1=发现不一致/缺失/错误; 2=用法或清单错误。
    4. --quick 仅比 size+mtime，极快，适合年度粗筛；可疑项再全量。
    5. 全程 UTF-8。

用法见: metadata_verify.py --help
"""
import argparse
import hashlib
import os
import sys
from pathlib import Path

CHUNK = 4 * 1024 * 1024
DEFAULT_MANIFEST = "checksums.tsv"


def file_hash(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def load_manifest(manifest_path):
    entries = []
    algo = None
    with open(manifest_path, encoding="utf-8") as mf:
        for line in mf:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("# algorithm="):
                    algo = line.split("=", 1)[1].strip()
                continue
            parts = line.split("\t")
            if len(parts) != 4:
                continue
            entries.append((parts[0], int(parts[1]), int(parts[2]), parts[3]))
    if algo is None:
        algo = "sha256"
    return entries, algo


def _under(fp, t):
    """fp 是否等于 t 或是 t 的后代(均须为绝对路径)。"""
    try:
        fp.relative_to(t)
        return True
    except ValueError:
        return False


def main():
    ap = argparse.ArgumentParser(
        prog="metadata_verify.py",
        description="依据清单校验文件完整性。默认校验清单中的全部条目。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  metadata_verify.py                  # 用脚本同目录的 checksums.tsv 校验全部\n"
               "  metadata_verify.py -m X:\\my.tsv     # 指定清单\n"
               "  metadata_verify.py D:\\photos        # 只校验这些路径(仍按清单比对)\n"
               "  metadata_verify.py --quick          # 仅比 size+mtime, 快\n"
               "  metadata_verify.py --report-extra   # 额外报告磁盘多出的文件\n"
               "  metadata_verify.py --root W:\\       # 跨盘比对: 目标树根(如挂载的 ISO 盘符)\n",
    )
    ap.add_argument("targets", nargs="*", default=None,
                    help="限定验证的文件/目录(可选)；默认校验清单全部")
    ap.add_argument("--manifest", "-m", default=None,
                    help="清单路径，默认: 脚本同目录/checksums.tsv")
    ap.add_argument("--quick", action="store_true",
                    help="仅比对 size+mtime，不重算哈希(快)")
    ap.add_argument("--algorithm", "-a", default=None,
                    help="覆盖清单中的算法(一般无需)")
    ap.add_argument("--report-extra", action="store_true",
                    help="额外扫描磁盘、报告清单中没有的文件")
    ap.add_argument("--root", default=None,
                    help="目标树的结构根目录。必须与生成清单时用的 --root 一致"
                         "(即目标树与源树共享的相对结构)，否则路径对不上。"
                         "默认=清单所在目录。")
    ap.add_argument("--quiet", action="store_true",
                    help="只输出异常项(OK 不打印)")
    args = ap.parse_args()

    script_dir = Path(__file__).resolve().parent
    manifest_path = (Path(args.manifest).resolve()
                     if args.manifest else script_dir / DEFAULT_MANIFEST)
    if not manifest_path.exists():
        print(f"[ERROR] 找不到清单: {manifest_path}", file=sys.stderr)
        sys.exit(2)
    base_dir = (Path(args.root).resolve() if args.root
                else manifest_path.parent)

    entries, algo = load_manifest(manifest_path)
    if args.algorithm:
        algo = args.algorithm
    if not args.quiet:
        print(f"载入 {len(entries)} 条, 算法={algo}, 基准={base_dir}",
              file=sys.stderr)

    # 限定验证范围
    target_rels = None
    if args.targets:
        target_rels = set()
        for t in args.targets:
            p = Path(t)
            if not p.is_absolute():
                p = Path.cwd() / p
            target_rels.add(p.resolve())

    ok = miss = mismatch = error = 0
    for (h, sz, mt, rel) in entries:
        fp = Path(base_dir) / rel
        if target_rels is not None:
            fr = fp.resolve()
            if not any(fr == t or _under(fr, t) for t in target_rels):
                continue
        if not fp.exists():
            print(f"MISSING\t{rel}")
            miss += 1
            continue
        try:
            st = fp.stat()
            if args.quick:
                if int(st.st_size) == sz and int(st.st_mtime) == mt:
                    if not args.quiet:
                        print(f"OK\t{rel}")
                    ok += 1
                else:
                    print(f"CHANGED\t{rel}")
                    mismatch += 1
                continue
            if int(st.st_size) != sz:
                print(f"MISMATCH(size)\t{rel}")
                mismatch += 1
                continue
            cur = file_hash(fp, algo)
            if cur != h:
                print(f"MISMATCH(hash)\t{rel}")
                mismatch += 1
                continue
            if not args.quiet:
                print(f"OK\t{rel}")
            ok += 1
        except Exception as e:
            print(f"ERROR(read fail, 可能坏扇区)\t{rel}\t-> {e}")
            error += 1

    if args.report_extra:
        manifest_rels = {e[3] for e in entries}
        extra = 0
        for root, dirs, names in os.walk(base_dir):
            for n in names:
                fp = Path(root) / n
                rel = os.path.relpath(str(fp), str(base_dir)).replace(os.sep, "/")
                if rel not in manifest_rels and fp.name not in (
                        "checksums.tsv", "metadata_gen.py", "metadata_verify.py"):
                    print(f"EXTRA\t{rel}")
                    extra += 1
        if not args.quiet:
            print(f"[report-extra] 多出 {extra} 个文件", file=sys.stderr)

    print(f"\n[SUMMARY] OK={ok} MISMATCH={mismatch} "
          f"MISSING={miss} ERROR={error}", file=sys.stderr)
    sys.exit(0 if (mismatch == 0 and miss == 0 and error == 0) else 1)


if __name__ == "__main__":
    main()
