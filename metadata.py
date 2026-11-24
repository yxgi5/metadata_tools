#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
metadata.py - 磁盘文件校验和清单的【生成 + 校验】二合一工具

子命令:
  gen      扫描目录/文件，生成校验和清单 (manifest)
  verify   依据清单校验文件完整性

设计要点(相比“只记 sha256”):
    1. 路径用【相对路径】；基准默认=清单文件所在目录，可用 --root 指定为任意
       目录，从而支持跨盘/跨目录比对(gen/verify 须用同一 --root)。
    2. 全程 UTF-8，正确处理中文/特殊文件名。
    3. 大文件分块(4MB)读取，内存恒定。
    4. 单文件读取失败(坏扇区)只告警并跳过，不中断整轮。
    5. 清单先写临时文件再原子改名，中途崩溃不留半截。
    6. 自动排除清单自身与本工具，避免自引用/抖动。
    7. 可选 --algorithm (sha256/sha1/md5/blake2b)，默认 sha256。
    8. verify 退出码: 0=全过; 1=不一致/缺失/错误; 2=用法或清单错误。
    9. verify --quick 仅比 size+mtime(快); --report-extra 报告清单外文件。

用法:
  metadata.py gen                 # 扫当前目录 -> 脚本同目录/checksums.tsv
  metadata.py gen D:\\photos      # 扫指定目录
  metadata.py gen a.iso b.iso     # 只记这两个文件
  metadata.py gen -m X:\\my.tsv   # 指定清单位置
  metadata.py gen --append -m X:\\my.tsv a.iso
                                 # 增量：a.iso 已有则跳过，无则追加
  metadata.py gen --update-one -m X:\\my.tsv a.iso
                                 # 单文件更新：相同不变/不同备份后改/无则追加
  metadata.py verify              # 用脚本同目录清单校验全部
  metadata.py verify -m X:\\my.tsv
  metadata.py verify D:\\photos   # 只校验这些路径
  metadata.py verify --quick      # 仅比 size+mtime
  metadata.py verify --report-extra
详见: metadata.py gen --help / metadata.py verify --help
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
TOOL_NAMES = {"metadata.py", "checksums.tsv"}


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


def _under(fp, t):
    """fp 是否等于 t 或是 t 的后代(均须为绝对路径)。"""
    try:
        fp.relative_to(t)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# gen
# --------------------------------------------------------------------------
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
    """按已有行顺序重写清单（upsert/delete 用），原子替换。"""
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
        # 校验变化：备份 -> 替换该行
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


def cmd_gen(args):
    script_path = Path(__file__).resolve()
    script_dir = script_path.parent
    manifest_path = (Path(args.manifest).resolve()
                     if args.manifest else script_dir / DEFAULT_MANIFEST)
    base_dir = (Path(args.root).resolve() if args.root
                else manifest_path.parent)

    # 单文件 upsert：独立开关 --update-one；与 --append 语义完全分开
    if getattr(args, "update_one", False):
        _update_one(args, manifest_path, base_dir)

    # 增量追加：读取已有清单，已记录的路径直接跳过(不读盘)
    appending = getattr(args, "append", False)
    existing = {}       # relpath -> 原始整行
    meta = {}
    if appending:
        if manifest_path.exists():
            existing, meta = _load_manifest_raw(manifest_path)
            old_algo = meta.get("algorithm")
            if old_algo and old_algo != args.algorithm:
                print(f"[INFO] 追加模式沿用清单算法 {old_algo}（忽略 -a {args.algorithm}）",
                      file=sys.stderr)
                args.algorithm = old_algo
            old_base = meta.get("base")
            if old_base and old_base != str(base_dir):
                print(f"[WARN] 清单 base={old_base} 与当前 base={base_dir} 不一致，"
                      f"相对路径可能对不上；请用相同 --root。", file=sys.stderr)
            print(f"[INFO] 增量模式：已有 {len(existing)} 条，仅计算新增文件。",
                  file=sys.stderr)
        else:
            print(f"[INFO] 清单不存在，按全量生成：{manifest_path}", file=sys.stderr)

    files = iter_files(args.targets, args.follow_symlinks)
    exclude = {manifest_path, script_path}
    files = [f for f in files
             if f not in exclude and f.name not in TOOL_NAMES]
    files.sort(key=lambda p: str(p).lower())

    if not args.quiet:
        print(f"扫描到 {len(files)} 个文件，算法={args.algorithm}"
              f"{'（增量追加）' if appending else ''}", file=sys.stderr)
        print(f"清单将写入: {manifest_path}", file=sys.stderr)

    tmp = manifest_path.with_name(manifest_path.name + ".tmp")
    count = 0
    skipped = 0
    total_bytes = 0
    read_errors = 0
    t0 = time.time()
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as out:
            out.write("# disk-metadata-manifest v1\n")
            out.write(f"# algorithm={args.algorithm}\n")
            created = (meta.get("created") if appending else None) or \
                      time.strftime('%Y-%m-%dT%H:%M:%S%z')
            out.write(f"# created={created}\n")
            out.write(f"# base={base_dir}\n")
            out.write("# hash\tsize\tmtime\trelpath\n")
            if appending and existing:
                for raw in existing.values():
                    out.write(raw + "\n")
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
                    h = file_hash(f, args.algorithm)
                    out.write(f"{h}\t{st.st_size}\t{int(st.st_mtime)}\t{rel}\n")
                    count += 1
                    total_bytes += st.st_size
                except Exception as e:
                    print(f"[ERROR] 读取失败(可能坏扇区): {f} -> {e}",
                          file=sys.stderr)
                    read_errors += 1
                if not args.quiet and count and count % 500 == 0:
                    el = time.time() - t0
                    print(f"  {count} 新文件 / {total_bytes/1e9:.1f} GB "
                          f"/ {el:.0f}s ...", file=sys.stderr)
            out.flush()
            os.fsync(out.fileno())
        _replace_with_retry(tmp, manifest_path)
    except KeyboardInterrupt:
        if tmp.exists():
            tmp.unlink()
        print("\n[ABORT] 已中断，临时文件已清理。", file=sys.stderr)
        sys.exit(130)

    if not args.quiet:
        msg = f"完成: 新增 {count} 文件"
        if appending:
            msg += f"，跳过 {skipped} 个已有"
        msg += f", {total_bytes/1e9:.2f} GB -> {manifest_path}"
        print(msg, file=sys.stderr)
    if read_errors:
        print(f"[SUMMARY] {read_errors} 个文件读取失败(见上)，"
              f"已从清单排除，请排查坏扇区。", file=sys.stderr)
    sys.exit(0)


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------
def cmd_verify(args):
    script_dir = Path(__file__).resolve().parent
    manifest_path = (Path(args.manifest).resolve()
                     if args.manifest else script_dir / DEFAULT_MANIFEST)
    if not manifest_path.exists():
        print(f"[ERROR] 找不到清单: {manifest_path}", file=sys.stderr)
        sys.exit(2)
    base_dir = (Path(args.root).resolve() if args.root
                else manifest_path.parent)

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
    if args.algorithm:
        algo = args.algorithm
    if not args.quiet:
        print(f"载入 {len(entries)} 条, 算法={algo}, 基准={base_dir}",
              file=sys.stderr)

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
                if rel not in manifest_rels and fp.name not in TOOL_NAMES:
                    print(f"EXTRA\t{rel}")
                    extra += 1
        if not args.quiet:
            print(f"[report-extra] 多出 {extra} 个文件", file=sys.stderr)

    print(f"\n[SUMMARY] OK={ok} MISMATCH={mismatch} "
          f"MISSING={miss} ERROR={error}", file=sys.stderr)
    sys.exit(0 if (mismatch == 0 and miss == 0 and error == 0) else 1)


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        prog="metadata.py",
        description="磁盘文件校验和清单 生成/校验 二合一工具。",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="生成校验和清单",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    g.add_argument("targets", nargs="*", default=["."],
                   help="要扫描的文件或目录(可多个)，默认当前目录")
    g.add_argument("--manifest", "-m", default=None,
                   help="清单输出路径，默认: 脚本同目录/checksums.tsv")
    g.add_argument("--algorithm", "-a", default="sha256",
                   choices=["sha256", "sha1", "md5", "blake2b"],
                   help="哈希算法 (默认 sha256)")
    g.add_argument("--follow-symlinks", action="store_true",
                   help="跟随符号链接(默认不跟随，避免循环)")
    g.add_argument("--root", default=None,
                   help="相对路径基准目录。gen 与 verify 必须用同一个 root "
                        "才能跨盘/跨目录比对。默认=清单所在目录。")
    g.add_argument("--append", action="store_true",
                   help="增量模式：读取已有清单，只计算新增文件的哈希并追加，"
                        "已记录路径跳过(不读盘)。目标可传目录或具体文件；"
                        "对具体文件同样是已记录就跳过。清单不存在时等价于全量生成。")
    g.add_argument("--update-one", "--upsert", dest="update_one",
                   action="store_true",
                   help="单文件更新模式：已有记录则核对哈希——相同则清单不变并提示，"
                        "不同则先备份原清单再更新；无记录则追加。"
                        "需恰好一个文件参数；与 --append 同用时本模式优先。")
    g.add_argument("--quiet", "-q", action="store_true", help="关闭进度输出")
    g.set_defaults(func=cmd_gen)

    v = sub.add_parser("verify", help="校验清单",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    v.add_argument("targets", nargs="*", default=None,
                   help="限定验证的文件/目录(可选)；默认校验清单全部")
    v.add_argument("--manifest", "-m", default=None,
                   help="清单路径，默认: 脚本同目录/checksums.tsv")
    v.add_argument("--quick", action="store_true",
                   help="仅比对 size+mtime，不重算哈希(快)")
    v.add_argument("--algorithm", "-a", default=None, help="覆盖清单中的算法")
    v.add_argument("--report-extra", action="store_true",
                   help="额外扫描磁盘、报告清单中没有的文件")
    v.add_argument("--root", default=None,
                   help="目标树的结构根目录。必须与 gen 时用的 --root 一致。"
                        "默认=清单所在目录。")
    v.add_argument("--quiet", action="store_true", help="只输出异常项")
    v.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
