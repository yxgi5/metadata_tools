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
    1. 路径相对【基准目录】解析；--root 是清单相对路径的起点(通常是数据目录
       的父目录，不是数据目录本身)，默认=清单所在目录。真实路径=root+清单相对路径。
       例: 清单记 securefs_cipher/a.bin、数据在 H:\\securefs_cipher\\a.bin,
           则 --root 应为 H:\\ (不是 H:\\securefs_cipher)。gen/verify 层级须一致。
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
import time
from pathlib import Path

CHUNK = 4 * 1024 * 1024
DEFAULT_MANIFEST = "checksums.tsv"


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
               "  metadata_verify.py a.bin b.bin      # 只校验具体文件(清单相对路径或绝对路径均可)\n"
               "  metadata_verify.py --quick          # 仅比 size+mtime, 快\n"
               "  metadata_verify.py --report-extra   # 额外报告磁盘多出的文件\n"
               "  metadata_verify.py --root H:\\       # 清单路径相对盘根: 数据实际在 H:\\securefs_cipher\\...\n",
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
                    help="清单相对路径的起点(通常是数据目录的父目录，不是数据目录本身)："
                         "真实路径 = root + 清单相对路径。默认=清单所在目录。"
                         "必须与 gen 时的 root 层级一致(盘符可换)。"
                         "例: 清单记 securefs_cipher/a.bin、数据在 H:\\securefs_cipher\\a.bin"
                         " -> 用 --root H:\\；填 H:\\securefs_cipher 会全部 MISSING。")
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

    # 目标过滤：既接受磁盘绝对路径，也接受清单里的相对路径(相对 base_dir)。
    target_abs = None
    if args.targets:
        target_abs = set()
        for t in args.targets:
            p = Path(t)
            if p.is_absolute():
                target_abs.add(p.resolve())
            else:
                target_abs.add((base_dir / t).resolve())
                target_abs.add((Path.cwd() / t).resolve())

    todo = []
    for (h, sz, mt, rel) in entries:
        fp = Path(base_dir) / rel
        if target_abs is not None:
            fr = fp.resolve()
            if not any(fr == ta or _under(fr, ta) for ta in target_abs):
                continue
        todo.append((h, sz, mt, rel, fp))

    if args.targets and not todo:
        print("[ERROR] 指定的目标在清单中没有匹配项。", file=sys.stderr)
        print("        可传磁盘绝对路径(如 H:\\securefs_cipher\\a.bin)、"
              "清单相对路径(如 securefs_cipher/a.bin)或目录。", file=sys.stderr)
        sys.exit(2)

    grand_total = sum(sz for (_h, sz, _mt, _rel, _fp) in todo)
    target_count = len(todo)
    if not args.quiet:
        print(f"待校验 {target_count} 条，共 {_fmt_bytes(grand_total)}",
              file=sys.stderr)

    ok = miss = mismatch = error = 0
    done_bytes = 0
    t0 = time.time()
    progress_dirty = [False]

    def _progress(idx, rel):
        if args.quiet:
            return
        if progress_dirty[0]:
            sys.stderr.write("\r" + " " * 100 + "\r")
            progress_dirty[0] = False
        el = time.time() - t0
        speed = done_bytes / el if el > 0 else 0
        remain = max(0, grand_total - done_bytes)
        eta = remain / speed if speed > 0 else 0
        pct = idx / target_count * 100 if target_count else 100.0
        line = (f"[{idx:4d}/{target_count:4d}] {pct:5.1f}% | "
                f"{_fmt_bytes(done_bytes)}/{_fmt_bytes(grand_total)} | "
                f"{_fmt_bytes(speed)}/s | ETA {_fmt_eta(eta)} | {rel}")
        sys.stderr.write(line + "\n")
        sys.stderr.flush()

    for idx, (h, sz, mt, rel, fp) in enumerate(todo, 1):
        if not fp.exists():
            print(f"MISSING\t{rel}")
            miss += 1
        else:
            try:
                st = fp.stat()
                matched = False
                if args.quick:
                    matched = (int(st.st_size) == sz and int(st.st_mtime) == mt)
                    if not matched:
                        print(f"CHANGED\t{rel}")
                        mismatch += 1
                elif int(st.st_size) != sz:
                    print(f"MISMATCH(size)\t{rel}")
                    mismatch += 1
                else:
                    def _cb(done, _f=fp, _sz=sz):
                        progress_dirty[0] = True
                        el2 = time.time() - t0
                        sp2 = (done_bytes + done) / el2 if el2 > 0 else 0
                        p2 = done / _sz * 100 if _sz else 0
                        sys.stderr.write(
                            f"\r  |-{_f.name}: {_fmt_bytes(done)}"
                            f"/{_fmt_bytes(_sz)} ({p2:.0f}%) {_fmt_bytes(sp2)}/s"
                        )
                        sys.stderr.flush()

                    cur = file_hash(fp, algo,
                                    progress_cb=_cb if not args.quiet else None)
                    if progress_dirty[0]:
                        sys.stderr.write("\r" + " " * 100 + "\r")
                        progress_dirty[0] = False
                    if cur == h:
                        matched = True
                    else:
                        print(f"MISMATCH(hash)\t{rel}")
                        mismatch += 1
                if matched:
                    if not args.quiet:
                        print(f"OK\t{rel}")
                    ok += 1
            except Exception as e:
                if not args.quiet and progress_dirty[0]:
                    sys.stderr.write("\r" + " " * 100 + "\r")
                    progress_dirty[0] = False
                print(f"ERROR(read fail, 可能坏扇区)\t{rel}\t-> {e}")
                error += 1
        done_bytes += sz
        _progress(idx, rel)

    if args.report_extra:
        manifest_rels = {e[3] for e in todo}
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
