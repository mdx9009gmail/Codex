#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ANANSI 自研神经保护管线驱动（B1）—— 一条命令从 C 源到受保护二进制。

管线（对引擎六阶段 Full builder 的自研复刻，不含 ollvm/VMP；CHAMELEON
+ BLA 六泳道守卫已内建并默认全开——anti-emu/integrity/deny-attach/
churn/opaque/ai-decoy，见 --guards）：

    前端（docker 发行包 clang 22.1.8）
      ├─ neural 档案（默认，= 轮2 金标准档案）：
      │    clang -S -emit-llvm -x c -O1 -Xclang -disable-lifetime-markers
      │    → input.ll（无归一化阶段）
      └─ raw 档案（--frontend raw，= 轮1 集成保护档案）：
           clang <全硬化旗标 -fno-inline -fpatchable-function-entry=5,0
           -fstack-protector-strong -mno-red-zone -Xclang -disable-llvm-passes
           -fno-jump-tables> → input.raw.ll
           → 归一化（clang -S -emit-llvm -O1 -x ir 重编译）→ input.ll
    plan_compiler.py    input.ll → module_plan.json（A1，0 字段差异）
    runtime_codegen.py  权重 npz + profile → runtime_{0,1,2} 三 TU（A2，字节一致）
    instrument_ll.py     input.ll + 票号表 → transformed.ll（B3，两轮字节一致）
    编译链接（docker）   clang -O3 -march=native -fno-unroll-loops
                         -fno-inline-functions -ffunction-sections
                         -fdata-sections -fwrapv -fno-strict-overflow
                         -ffp-contract=off（target_reach/report.json 实测命令）
                         transformed.o + runtime_*.o -lm → <output>

用法：
    python3 protect.py --source artifacts/engine-verify2/t2.c \
        --output my_prot --weight-npz src-neural-wip/_anansi_t2_module_weights.npz \
        --ticket-table tickets.json          # 其余参数缺省

注意：票号/tag 为 build 会话随机值（引擎不可复现），复现金标准时作为输入表
传入（轮2：2659911325400107137 / 9485348196553556760，tag 91ab756d3b57d9f3）。
缺省从 --profile 的 boundary_cases 提取票号、tags 提取 TAG_IR。
"""

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

# 引擎前端固定旗标面（f_001f5c10.c:1619-1695，notes-normalization-ticket §2）
FRONTEND_BASE = ["-S", "-emit-llvm", "-x", "c", "-O1",
                 "-Xclang", "-disable-lifetime-markers"]
FRONTEND_RAW_EXTRA = ["-fno-inline", "-fpatchable-function-entry=5,0",
                      "-fstack-protector-strong", "-fno-inline",
                      "-mno-red-zone", "-Xclang", "-disable-llvm-passes",
                      "-fno-jump-tables"]
NORMALIZE_ARGS = ["-S", "-emit-llvm", "-O1", "-x", "ir"]

# 运行时编译/链接旗标(target_reach/report.json compile_commands 实测)
# M1/D5: -march=native → x86-64(SSE2 基线):stub 需可移植基线;模板
# dense/ragged 本就有标量路径,不依赖 native 扩展。其余旗标不动
# (数值契约:-ffp-contract=off 必须保留,红线 3)。
RT_FLAGS = ["-O3", "-march=x86-64", "-fno-unroll-loops",
            "-fno-inline-functions", "-ffunction-sections",
            "-fdata-sections", "-fwrapv", "-fno-strict-overflow",
            "-ffp-contract=off"]


def sh(argv, **kw):
    print("+", " ".join(argv[:8]), "..." if len(argv) > 8 else "",
          file=sys.stderr)
    return subprocess.run(argv, check=True, **kw)


def docker_sh(script, workdir, args):
    workdir = os.path.abspath(workdir)
    if getattr(args, "native", False):
        return native_sh(script, workdir, args)
    argv = ["docker", "run", "--rm", "--platform", "linux/amd64",
            "-v", f"{args.dist}:/dist:ro",
            "-v", f"{workdir}:/w", "-w", "/w"]
    for host, cont in extra_mounts(args):
        argv += ["-v", f"{host}:{cont}"]
    argv += [args.image, "sh", "-c", script]
    print("+ docker sh (workdir=%s, mounts=%s)" % (workdir,
                                                   extra_mounts(args)),
          file=sys.stderr)
    proc = subprocess.run(argv)
    if proc.returncode != 0:
        raise SystemExit(f"protect: docker step failed (rc={proc.returncode})")


def native_sh(script, workdir, args):
    """原生执行(README 官方替代,无 docker)。

    本机 WSL 即 linux/amd64,直接以宿主 sh 运行各阶段脚本:
      /dist/bin/clang → <args.dist>/bin/clang
      /w/             → <workdir>/
      /out            → <workdir>/out
    调用方需以宿主真实路径传 --dist;--include 与多函数 --source-path
    在原生模式下即宿主路径(无挂载概念,原样传给 clang)。
    """
    dist = os.path.abspath(args.dist)
    workdir = os.path.abspath(workdir)
    # 两阶段占位符替换:workdir/dist 路径本身可能含 "/out"、"/w/" 等
    # 子串(如 .../work/out/...),直接顺序替换会自我污染。
    s = script.replace("/dist/bin/clang", "\x01CLANG\x01")
    s = s.replace("/w/", "\x01W\x01")
    s = s.replace("/out", "\x01OUT\x01")
    s = s.replace("\x01CLANG\x01", dist + "/bin/clang")
    s = s.replace("\x01W\x01", workdir + "/")
    s = s.replace("\x01OUT\x01", os.path.join(workdir, "out"))
    print("+ native sh (workdir=%s)" % workdir, file=sys.stderr)
    if sys.platform == "win32":
        # Windows → WSL 路径转换
        def to_wsl(p):
            p = os.path.abspath(p)
            d, r = os.path.splitdrive(p)
            return "/mnt/" + d[0].lower() + r.replace("\\", "/")
        w_workdir = to_wsl(workdir)
        w_dist = to_wsl(dist)
        # 重新替换为 WSL 路径
        s = script.replace("/dist/bin/clang", "\x01CLANG\x01")
        s = s.replace("/w/", "\x01W\x01")
        s = s.replace("/out", "\x01OUT\x01")
        s = s.replace("\x01CLANG\x01", w_dist + "/bin/clang")
        s = s.replace("\x01W\x01", w_workdir + "/")
        s = s.replace("\x01OUT\x01", w_workdir + "/out")
        proc = subprocess.run(["wsl", "-e", "bash", "-c",
                               f"cd {w_workdir} && {s}"])
    else:
        proc = subprocess.run(["sh", "-c", s], cwd=workdir)
    if proc.returncode != 0:
        raise SystemExit(f"protect: native step failed (rc={proc.returncode})")


def frontend_flags(args):
    """前端透传旗标：--cflag 原样 + --include/--define 展开 + -fno-inline
    （引擎 whibo construction.json 实测：neural 档案含 -fno-inline）。

    M2/D1 --stub-tu：对齐 wbp stub 构建(wbp/Makefile stub-x86_64 旗标集)
    ——freestanding/PIC/无栈保护/无跳转表，并注入 -DWBP_ARCH_X86_64 与
    -DNNOBF_FREESTANDING(runtime 侧模板宏由后者激活)。"""
    flags = list(args.cflag or [])
    for inc in args.include or []:
        flags.append("-I" + inc)
    for d in args.define or []:
        flags.append("-D" + d)
    if getattr(args, "stub_tu", False):
        # -fvisibility=hidden 与 runtime 编译一致(M3 GOT 修正):
        # 前端声明与 runtime 定义可见性匹配,避免 default 声明走 GOT。
        flags += ["-fPIC", "-ffreestanding", "-fno-stack-protector",
                  "-fno-jump-tables", "-fvisibility=hidden",
                  "-DWBP_ARCH_X86_64",
                  "-DNNOBF_FREESTANDING"]
    return flags


def extra_mounts(args):
    """docker 额外挂载：--mount 显式 + --include/-I 路径自动挂载（容器
    路径 = 引擎真值路径，如 /whibo）。去重保序。"""
    mounts = []
    for m in args.mount or []:
        host, cont = m.split(":", 1)
        mounts.append((os.path.abspath(host), cont))
    for inc in args.include or []:
        p = inc if os.path.isabs(inc) else os.path.abspath(inc)
        if os.path.isdir(p):
            mounts.append((p, inc))
    seen, out = set(), []
    for host, cont in mounts:
        if (host, cont) not in seen:
            seen.add((host, cont))
            out.append((host, cont))
    return out


def py(script, *argv):
    return sh([sys.executable, os.path.join(HERE, script), *argv])


# ---------------------------------------------------------------------------
def run_frontend(args, workdir, src_name):
    """阶段①：clang 前端（+raw 档案时的归一化），源码 staging 到 /out/。

    --functions 多函数模式对齐引擎 whibo 实测命令：源码以真值路径
    （--source-path 容器路径）编译，neural 档案附 -fno-inline，透传
    -D/-I 旗标（construction.json: clang -S -emit-llvm -x c -O1
    -Xclang -disable-lifetime-markers -fno-inline -I... -D_GNU_SOURCE）。
    """
    ff = frontend_flags(args)
    # 单函数模式沿用 R2 锚点 staging（/out/<src>，source_filename 对齐）；
    # 多函数模式以引擎真值源码路径编译（--source-path，如 /whibo/harness_42.c）
    if args.functions and args.source_path:
        stage = ("[ {sp} = /w/{src} ] || cp /w/{src} {sp}; "
                 ).format(sp=args.source_path, src=src_name)
        src_path = args.source_path
    else:
        stage = "cp /w/{src} /out/{src}; ".format(src=src_name)
        src_path = f"/out/{src_name}"
    if args.frontend == "neural":
        noinline = ["-fno-inline"] if args.functions else []
        script = (
            "mkdir -p /out && " + stage +
            "/dist/bin/clang {base} {noinline} {ff} {sp} -o /w/input.ll"
        ).format(base=" ".join(FRONTEND_BASE),
                 noinline=" ".join(noinline), ff=" ".join(ff), sp=src_path)
        docker_sh(script, workdir, args)
    else:  # raw 档案：全旗标 + 归一化（clang -O1 IR 重编译）
        script = (
            "mkdir -p /out && " + stage +
            "/dist/bin/clang -include stdio.h {base} {ff} {extra} {sp} "
            "-o /w/input.raw.ll && "
            "/dist/bin/clang {norm} /w/input.raw.ll -o /w/normalized.ll && "
            "cp /w/normalized.ll /w/input.ll"
        ).format(base=" ".join(FRONTEND_BASE), ff=" ".join(ff),
                 extra=" ".join(FRONTEND_RAW_EXTRA),
                 norm=" ".join(NORMALIZE_ARGS), sp=src_path)
        docker_sh(script, workdir, args)


def check_plan_profile(workdir, profile, tickets, region_gaps=False):
    """构建期一致性断言（引擎 'hybrid boundary contract does not match
    regions' 的自研版）：派生计划的帧布局/槽位/步数必须与 runtime profile
    的 boundary_cases 逐项对齐，否则链接产物必然行为错误。"""
    import instrument_ll as IL
    text = open(os.path.join(workdir, "input.ll")).read()
    IL._ensure_module_ctx(text)          # STRUCT_TYPES/FUNC_SIGS（进程级）
    fname, blocks, *_ = IL.parse_function(text)
    specs, n_frame = IL.analyze(fname, blocks, region_gaps=region_gaps)
    plan = json.load(open(os.path.join(workdir, "module_plan.json")))
    plan0 = plan["plans"][0]
    values = {v["key"]: v for v in plan0["values"]}

    cases = profile["boundary_cases"]
    if len(cases) != len(specs):
        raise SystemExit(
            f"protect: plan has {len(specs)} regions but runtime profile has "
            f"{len(cases)} boundary cases — frontend/profile mismatch?")
    for sp, case in zip(specs, cases):
        if int(tickets[str(sp.ridx)]) != int(case["ticket"]):
            raise SystemExit(f"protect: ticket mismatch at region {sp.ridx}")
        # 帧布局
        for pi, pi_json in zip(sp.ptr_ins, case["ptr_in"]):
            if pi[1] != pi_json["frame"]:
                raise SystemExit(
                    f"protect: region {sp.ridx} ptr_in frame {pi[1]} != "
                    f"profile {pi_json['frame']}")
        for si, si_json in zip(sp.scalar_ins, case["scalar_in"]):
            if si[2] != si_json["frame"]:
                raise SystemExit(
                    f"protect: region {sp.ridx} scalar_in frame {si[2]} != "
                    f"profile {si_json['frame']}")
        outs = case.get("outs") or ([case["out"]] if case.get("out") else [])
        if len(outs) != len(sp.outs):
            raise SystemExit(
                f"protect: region {sp.ridx} has {len(sp.outs)} live-outs but "
                f"profile exports {len(outs)}")
        for oi, oi_json in zip(sp.outs, outs):
            if oi[2] != oi_json["frame"]:
                raise SystemExit(
                    f"protect: region {sp.ridx} out frame {oi[2]} != "
                    f"profile {oi_json['frame']}")
        # 计划槽位（运行时 sync/commit/export 的 slot 必须与计划一致）
        region = plan0["regions"][sp.ridx]
        for k, si_json in zip(region["live_in_values"], case["scalar_in"]):
            if values[k]["slot"] != si_json["slot"]:
                raise SystemExit(
                    f"protect: region {sp.ridx} live-in slot "
                    f"{values[k]['slot']} != profile {si_json['slot']}")
        for k, oi_json in zip(region["live_out_values"], outs):
            if values[k]["slot"] != oi_json["slot"]:
                raise SystemExit(
                    f"protect: region {sp.ridx} live-out slot "
                    f"{values[k]['slot']} != profile {oi_json['slot']}")
        # 动作区间（profile exec = [action_start, action_count]，
        # 即 nnobf_execute_range(ctx, start, count) 的两个实参）
        if [region["action_start"],
                region["action_count"]] != case["exec"]:
            raise SystemExit(
                f"protect: region {sp.ridx} exec "
                f"[{region['action_start']},"
                f"{region['action_count']}] != profile {case['exec']}")
    print("protect: plan ↔ runtime profile contract OK "
          f"({len(specs)} regions, frame [{n_frame} x i64])", file=sys.stderr)


# ---------------------------------------------------------------------------
# CHAMELEON 守卫（自 anansi-neural-sdk-v0.1-antidebug 移植）：
#   anti-emu/integrity = IR 级（guards_ir.py，插桩后 transformed.ll 就地
#   重写，与神经边界协议正交：入口序在边界序之前、折叠在 live-out 读回
#   之后）；deny-attach = C 单元（guard_deny_attach.c 编入链接）。
GUARD_C = os.path.join(HERE, "guard_deny_attach.c")


def guards_list(args):
    return [g.strip() for g in (args.guards or "").split(",") if g.strip()]


def xor_mask_active(args):
    """circuit-under-NN 泳道（AntiReverse circuit_v1 XOR 秘密共享移植）：
    计划级 share 域变换，全部 share 运算由神经核心执行。

    antireverse v0.2 新泳道（main() 处归一化已自动补 xor-mask）：
    nonce-mask（consumer_fused_v1 运行时 nonce 派生掩码）/ share-encode
    （stateful_v34 per-share 槽位驻留编码）——二者为 xor-mask 的硬化
    模式，激活即蕴含本泳道。"""
    return "xor-mask" in guards_list(args)


def nonce_mask_active(args):
    """nonce-mask 泳道：split/刷新掩码运行期由区域 nonce（integer
    live-in 混合）派生，掩码不再是计划常量。"""
    return "nonce-mask" in guards_list(args)


def share_encode_active(args):
    """share-encode 泳道：槽位驻留 share 以 rot+salt+additive 独立编码
    （参数 seed 派生，对齐 stateful_v34 storage-plan）。"""
    return "share-encode" in guards_list(args)


# ---------------------------------------------------------------------------
# anti-reverse-prompt (arp) 泳道（anti-reverse-prompt_v0.0.md，v0.1 实现）：
# 声明式守卫（emit 契约）——文件（ARPNOTC1 拖车 + .rodata）/内存（NN 物化
# 缓冲 __sdk_arp_buf）/stderr（证据命中发射 TRUSTED_ACCESS_REQUIRED 帧）
# 三通道植入"拒绝逆向"声明。opt-in（--guards 显式加 arp）。
# ---------------------------------------------------------------------------
def arp_seed(args):
    """arp 语料种子：--guard-seed 优先；否则每构建随机一次并缓存于 args
    （arp_gen 与 post-link 拖车必须同语料——种子单点缓存）。"""
    if getattr(args, "_arp_seed", None) is None:
        args._arp_seed = (args.guard_seed if args.guard_seed is not None
                          else random.randrange(1 << 30))
    return args._arp_seed


def arp_gen(args, workdir, weights_npz=None):
    """arp build 侧生成（M0/M2）：guard_arp_text.c（.rodata 静态材料 +
    emit 帧字段）+ arp_codes.json（CANON 潜码表，--weights 提供时；直通
    模式无 NN 物化则免）。必须先于 runtime_codegen / guard 编译。"""
    if "arp" not in guards_list(args):
        return
    if not (args.arp_owner or "").strip():
        print("protect: arp WARNING --arp-owner empty — corpus uses generic "
              "'the copyright holder' (ethics redline: no fabricated legal "
              "identity; see anti-reverse-prompt_v0.0.md §4.6)",
              file=sys.stderr)
    cmd = ["guard_anti_reverse_prompt.py", "--emit-text", workdir,
           "--seed", str(arp_seed(args)),
           "--owner", args.arp_owner or ""]
    if args.arp_notice:
        cmd += ["--notice", args.arp_notice]
    if weights_npz:
        cmd += ["--weights", weights_npz]
    py(*cmd)
    print(f"protect: arp corpus generated (seed={arp_seed(args)}, "
          f"owner={'given' if (args.arp_owner or '').strip() else 'generic'}"
          f"{', codes baked' if weights_npz else ', passthrough (no codes)'})",
         file=sys.stderr)


# ---------------------------------------------------------------------------
# CHAMÆLEON M1-M6 evidence 泳道（chame-antidebug v0.2，规格 §2-§4）：
#   chame-tracer  M2  TracerPid 运行期轮询（K 节流 + M4 白名单）
#   chame-textkey M3  .text 折哈希即密钥（boot 全量 + 轮转；ELF post-link
#                     回填；平铺 stub 无回填点 → 自动 skip，规格 D5）
#   chame-hwbp    M4  fork self-debugger 读 DR7（boot 一次，fail-open）
#   chame-trap    M5  SIGTRAP 处理器即密钥（K 个自植入 int3 检查点）
#   chame-oracle  M6  x86 一致性 oracle（MXCSR.DAZ + DIV-flags 建期标定）
# M1（cpuid 3→7）内建于 anti-emu 泳道（guards_ir SIGNALS），非独立泳道。
# 响应契约：一律静默折叠（路由 A live-in / 路由 B 常量种子随 xor-mask
# 自动叠加）；--guard-strict 升级 exit 173（规格 D4）。默认关（D3）。
# ---------------------------------------------------------------------------
CHAME_LANES = ("chame-tracer", "chame-textkey", "chame-hwbp",
               "chame-trap", "chame-oracle")


def chame_lanes(args):
    return [g for g in guards_list(args) if g in CHAME_LANES]


def chame_active(args):
    return bool(chame_lanes(args))


def chame_defines(args):
    """chame 泳道 → runtime/guard TU 编译 -D 集（常量从 guard-seed 派生，
    构建可复现，规格 §3.4）。返回 '' 或 ' -D...' 串。"""
    if not chame_active(args):
        return ""
    g = chame_lanes(args)
    seed = args.guard_seed if args.guard_seed is not None else 0
    rng = random.Random((seed ^ 0xC4A4E) * 1000003 + 7)
    defs = ["-DNNOBF_GUARD_CHAME"]
    if "chame-tracer" in g:
        defs.append("-DNNOBF_CHAME_TRACER")
        defs.append("-DNNOBF_EV_POLL_K=%d" % rng.randrange(8, 33))
    if "chame-hwbp" in g:
        defs.append("-DNNOBF_CHAME_HWBP")
    if "chame-trap" in g:
        defs.append("-DNNOBF_CHAME_TRAP")
        defs.append("-DNNOBF_TRAP_K=%d" % rng.randrange(2, 5))
        defs.append("-DNNOBF_TRAP_C=0x%xull" % rng.getrandbits(48))
    if "chame-textkey" in g:
        defs.append("-DNNOBF_CHAME_TEXTKEY")
        defs.append("-DNNOBF_TK_ROT0=%d" % rng.randrange(0, 64))
    if "chame-oracle" in g:
        defs.append("-DNNOBF_CHAME_ORACLE")
    if xor_mask_active(args):
        defs.append("-DNNOBF_GUARD_SEED")     # 路由 B 自动叠加（D2）
    if args.guard_strict:
        defs.append("-DNNOBF_GUARD_STRICT")   # strict 升级（D4）
    return " " + " ".join(defs)


ORACLE_PROBE_C = r"""#include <stdio.h>
#include <stdint.h>
int main(void) {
    unsigned long f;
    __asm__ volatile("xor %%edx, %%edx\n\t"
                     "mov $1, %%eax\n\t"
                     "mov $3, %%ecx\n\t"
                     "div %%ecx\n\t"
                     "pushfq\n\t"
                     "popq %0"
                     : "=r"(f)
                     :
                     : "rax", "rcx", "rdx", "memory");
    printf("%lx\n", f & 0x8D5ul);
    return 0;
}
"""


def calibrate_oracle(args, workdir):
    """M6 DIV-flags 建期标定（规格 §4.6/V12a）：现场编译并运行探针（asm
    形态与运行时 CHAME 块逐字节一致）→ 干净环境 delta=0 的期望值。"""
    probe = os.path.join(workdir, "guard_oracle_probe.c")
    with open(probe, "w", encoding="utf-8") as f:
        f.write(ORACLE_PROBE_C)
    script = ("/dist/bin/clang -O2 /w/guard_oracle_probe.c "
              "-o /w/guard_oracle_probe && /w/guard_oracle_probe "
              "> /w/.oracle_calib")
    docker_sh(script, workdir, args)
    val = open(os.path.join(workdir, ".oracle_calib")).read().strip()
    if not re.fullmatch(r"[0-9a-f]{1,16}", val):
        raise SystemExit(f"protect: oracle calibration failed ({val!r})")
    return int(val, 16)


def crown_of(args):
    """守卫 crown 清单：多函数=--functions 解析；单函数=--function。"""
    if args.functions:
        f = args.functions
        if f.startswith("@"):
            return [l.strip() for l in open(f[1:]) if l.strip()]
        return [t for t in re.split(r"[,\s]+", f) if t]
    return [args.function]


CHURN_SLOTS = 32
CHURN_WORDS = 4


def gen_churn_c(seed):
    """Lane 6：从模板生成种子化 guard_state_churn.c（确定性）。"""
    rng = random.Random((seed ^ 0xC47) * 1000003)
    rows = []
    for i in range(CHURN_SLOTS):
        ws = [f"0x{rng.randrange(1 << 32):08x}u" for _ in range(CHURN_WORDS)]
        rows.append("    {" + ", ".join(ws) + "},")
    tpl = open(os.path.join(HERE, "guard_state_churn.c.template"),
               encoding="utf-8").read()
    return tpl.replace("__CHURN_INIT__", "\n".join(rows))


def apply_guards_step(args, workdir, src_ll):
    """⑥.5 守卫步骤：anti-emu/integrity/churn/opaque 重写 IR（就地），
    deny-attach/churn 拷贝/生成 C 守卫单元到 workdir 供编译链接。
    返回守卫清单。"""
    if getattr(args, "native_call_gate", None):
        from native_call_gate import apply as apply_native_call_gate
        gate_path = os.path.join(workdir, src_ll)
        roots = [x for x in re.split(r"[,\s]+", args.native_call_gate) if x]
        with open(gate_path, encoding="utf-8") as f:
            gated, manifest = apply_native_call_gate(f.read(), roots)
        with open(gate_path, "w", encoding="utf-8") as f:
            f.write(gated)
        with open(os.path.join(workdir, "native_call_gate.json"), "w") as f:
            json.dump(manifest, f, indent=2)
    g = guards_list(args)
    ir_guards = [x for x in ("anti-emu", "integrity", "churn", "opaque")
                 if x in g]
    if ir_guards:
        seed = args.guard_seed if args.guard_seed is not None \
            else random.randrange(1 << 30)
        py("guards_ir.py", os.path.join(workdir, src_ll),
           "-o", os.path.join(workdir, "guarded.ll"),
           "--crown", *crown_of(args),
           "--guards", ",".join(ir_guards), "--seed", str(seed))
        os.replace(os.path.join(workdir, "guarded.ll"),
                   os.path.join(workdir, src_ll))
        print(f"protect: guards applied {ir_guards} (seed={seed})",
              file=sys.stderr)
    if "deny-attach" in g:
        shutil.copyfile(GUARD_C, os.path.join(workdir, "guard_deny_attach.c"))
    if "churn" in g:
        # 若 __sdk_churn_step 已在 --functions 里（被神经化），
        # 跳过生成原生单元（避免重复符号链接错误）
        if "__sdk_churn_step" not in (args.functions or ""):
            seed = args.guard_seed if args.guard_seed is not None \
                else random.randrange(1 << 30)
            open(os.path.join(workdir, "guard_state_churn.c"), "w",
                 encoding="utf-8").write(gen_churn_c(seed))
        else:
            print("protect: churn neuralized (in --functions, "
                  "skipping native unit)", file=sys.stderr)
    if "seal" in g:
        shutil.copyfile(os.path.join(HERE, "guard_file_seal.c"),
                        os.path.join(workdir, "guard_file_seal.c"))
    if "arp" in g:
        # guard_arp_text.c（同目录 #include）由 arp_gen 生成于 workdir
        shutil.copyfile(os.path.join(HERE, "guard_arp.c"),
                        os.path.join(workdir, "guard_arp.c"))
    return g


def guard_cc_parts(args, cc, chame=True):
    """deny-attach/churn 编译/链接片段，返回 (编译行前缀, 链接对象)。

    guard.o / guard_sc.o 在 --link-mode objects 下留在 workdir 供外部
    链接接管（如 wbp stub 的 ld -T stub.lds）；ELF 模式追加进链接行。
    --stub-tu 模式额外定义 NNOBF_GUARD_NO_CONSTRUCTOR：跳过 constructor
    属性（平铺 stub 无 ELF 装载器，且 .init_array 孤儿节可能扰乱
    stub.lds 布局约束），执行点交给 runtime TU 的 __sdk_guard_boot 钩子。
    guard.o 命名沿用 v0.1-antidebug（wbp-anansi-link build_stub.sh 已
    验收依赖该名；churn 单元独立命名 guard_sc.o）。

    CHAMÆLEON M1-M6：guard 单元编译附 -DNNOBF_GUARD_CHAME（§3.3 序：
    TracerPid 检查 → __sdk_chame_boot（M4 先于 prctl）→ prctl）；
    chame 证据单元本体位于 runtime TU 模板（<<CHAME_GUARD>>），无独立
    .o——对 wbp build_stub.sh 的固定守卫对象清单零扰动。chame=False
    用于无可保护区域的直通构建（无 runtime TU → __sdk_chame_boot 无定义
    处，chame 泳道按规格 §2.2 降级为无操作，仅打印 skip 提示）。"""
    g = guards_list(args)
    pre, obj = "", ""
    if "deny-attach" in g:
        gcc = f"{cc} -c -x c /w/guard_deny_attach.c -o /w/guard.o"
        if getattr(args, "stub_tu", False):
            gcc += " -DNNOBF_GUARD_NO_CONSTRUCTOR"
        if chame:
            gcc += chame_defines(args)
        pre += gcc + " &&\n"
        obj += "/w/guard.o "
    if "churn" in g:
        # 神经化 churn 时不编译原生单元
        if "__sdk_churn_step" not in (args.functions or ""):
            pre += f"{cc} -c -x c /w/guard_state_churn.c -o /w/guard_sc.o &&\n"
            obj += "/w/guard_sc.o "
    if "seal" in g:
        pre += f"{cc} -c -x c /w/guard_file_seal.c -o /w/guard_fs.o &&\n"
        obj += "/w/guard_fs.o "
    if "arp" in g:
        # arp 守卫单元（guard_arp_text.c 经 #include 并入同一 TU——wbp 守卫
        # 对象清单只增 guard_arp.o 一项）。编译期宏按泳道组合/形态注入：
        #   NO_CONSTRUCTOR（stub）→ 执行点移交 _context_create 钩子；
        #   PASSTHROUGH（chame=False = 无 runtime TU 的直通构建）→ boot 期
        #   原生 memcpy 降级 + 剥离对 __sdk_arp_materialize 的 extern 引用；
        #   HAS_POISON（deny-attach 开）/ HAS_EV（chame 开且非直通）→ 证据
        #   源接线；REFRESH_K 从 --guard-seed 派生（chame_defines 惯例）。
        gcc = f"{cc} -c -x c /w/guard_arp.c -o /w/guard_arp.o"
        if getattr(args, "stub_tu", False):
            gcc += " -DNNOBF_GUARD_NO_CONSTRUCTOR"
        if not chame:
            gcc += " -DNNOBF_ARP_PASSTHROUGH"
        if "deny-attach" in g:
            gcc += " -DNNOBF_ARP_HAS_POISON"
        if chame and chame_active(args):
            gcc += " -DNNOBF_ARP_HAS_EV"
        seed = args.guard_seed if args.guard_seed is not None else 0
        rng = random.Random((seed ^ 0x4A50) * 1000003 + 7)
        gcc += " -DNNOBF_ARP_REFRESH_K=%d" % rng.randrange(8, 33)
        pre += gcc + " &&\n"
        obj += "/w/guard_arp.o "
    return pre, obj


# ---------------------------------------------------------------------------
# M3 textkey post-link 回填（规格 §4.3：期望哈希最终链接后才可知）：
# 纯 Python ELF64 解析（无 nm 依赖）→ 定位 __sdk_textkey_{ref,off,len,
# expect} 符号与 .text/.data 节 → 计算窗口折哈希（128B 切片 FNV-1a64 逐
# 一哈希 XOR，含尾片——与 CHAME 块 __sdk_chame_textkey_boot 逐位一致）
# → 回填三联（off/len/expect，.data 文件背书）→ strip（恢复 -s 基线）。
# ---------------------------------------------------------------------------
import struct


def guard_rt_def(args):
    """运行时 TU 编译宏：deny-attach 开启时激活模板 _context_create 的
    __sdk_guard_boot() 钩子（平铺 stub 无 ELF constructor，需显式 boot；
    ELF 场景与 constructor(101) 经 once 标志幂等）。

    CHAMÆLEON M1-M6：chame 泳道开 → -DNNOBF_GUARD_CHAME（证据单元 +
    boundary 钩子 + boot 调用）+ 泳道子集/常量 -D（chame_defines，
    guard-seed 派生 + M6 标定值——标定须先于本调用完成，否则 C 侧
    NNOBF_ORACLE_DIVFLAGS 未定义即编译失败）。"""
    d = " -DNNOBF_GUARD_DENY_ATTACH" if "deny-attach" in guards_list(args) \
        else ""
    if "arp" in guards_list(args):
        # arp 泳道：激活模板三钩子（_context_create boot / call_begin 首物化
        # / boundary 每 K 重物化+发射门）与 <<ARP_GUARD>> owner 单元
        d += " -DNNOBF_GUARD_ARP"
    if chame_active(args):
        d += chame_defines(args)
        if "chame-oracle" in chame_lanes(args):
            if getattr(args, "_oracle_divflags", None) is None:
                raise SystemExit("protect: chame-oracle requires build-time "
                                 "calibration (calibrate_oracle) before "
                                 "runtime compilation")
            d += " -DNNOBF_ORACLE_DIVFLAGS=0x%xul" % args._oracle_divflags
    return d


def _fnv1a64_bytes(b):
    h = 0xCBF29CE484222325
    for byte in b:
        h ^= byte
        h = (h * 0x100000001B3) & ((1 << 64) - 1)
    return h


def _textkey_fold(data, off, size):
    """窗口折哈希：128B 切片 FNV-1a64 XOR（含尾片）——与 C 侧一致。"""
    acc = 0
    pos, end = off, off + size
    while pos < end:
        n = min(128, end - pos)
        acc ^= _fnv1a64_bytes(data[pos:pos + n])
        pos += n
    return acc


def apply_textkey_backfill(args, bin_path, workdir):
    """M3 ELF 回填：patch __sdk_textkey 三联 → strip。返回描述 dict。"""
    data = bytearray(open(bin_path, "rb").read())
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit("protect: textkey backfill: not ELF64 LE")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    shs = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        sh_name, sh_type = struct.unpack_from("<II", data, base)
        sh_addr, sh_off, sh_size = struct.unpack_from("<QQQ", data, base + 16)
        sh_link = struct.unpack_from("<I", data, base + 40)[0]
        shs.append(dict(name=sh_name, type=sh_type, addr=sh_addr,
                        off=sh_off, size=sh_size, link=sh_link))
    shstr_off = shs[e_shstrndx]["off"]

    def secname(s):
        end = data.index(b"\0", shstr_off + s["name"])
        return data[shstr_off + s["name"]:end].decode()

    secs = {secname(s): s for s in shs}
    if ".text" not in secs or ".data" not in secs:
        raise SystemExit("protect: textkey backfill: .text/.data missing")

    syms = {}
    for s in shs:
        if s["type"] != 2:                # SHT_SYMTAB
            continue
        strtab = shs[s["link"]]
        pos = s["off"]
        end = s["off"] + s["size"]
        while pos + 24 <= end:
            st_name, _info, _other, _shndx, st_value, _st_size = \
                struct.unpack_from("<IBBHQQ", data, pos)
            if st_name:
                nend = data.index(b"\0", strtab["off"] + st_name)
                nm = data[strtab["off"] + st_name:nend].decode()
                if nm in ("__sdk_textkey_ref", "__sdk_textkey_off",
                          "__sdk_textkey_len", "__sdk_textkey_expect"):
                    syms[nm] = st_value
            pos += 24
    missing = [k for k in ("__sdk_textkey_ref", "__sdk_textkey_off",
                           "__sdk_textkey_len", "__sdk_textkey_expect")
               if k not in syms]
    if missing:
        raise SystemExit(f"protect: textkey backfill: symbols missing "
                         f"{missing}（链接需去 -s 以保留 symtab）")

    text = secs[".text"]
    dsec = secs[".data"]
    expect = _textkey_fold(bytes(data), text["off"], text["size"])
    off = text["addr"] - syms["__sdk_textkey_ref"]     # PIE 相对窗口

    def patch(sym, value):
        fo = dsec["off"] + (syms[sym] - dsec["addr"])
        struct.pack_into("<Q", data, fo, value)

    patch("__sdk_textkey_off", off & ((1 << 64) - 1))
    patch("__sdk_textkey_len", text["size"])
    patch("__sdk_textkey_expect", expect)
    with open(bin_path, "wb") as f:
        f.write(bytes(data))
    # strip（恢复 -s 基线；dist 无 llvm-strip → WSL/容器 strip）
    docker_sh("strip /w/" + os.path.basename(bin_path), workdir, args)
    return {"window_bytes": text["size"], "slices":
            (text["size"] + 127) // 128,
            "expect": "0x%016x" % expect, "off": off,
            "keep_unstripped": True}


def apply_post_link_guards(args, out_abs):
    """⑧ 后链接守卫：ai-decoy（BLA native.ts 植入策略移植）+ seal
    （文件 SHA-256 封印，原引擎第三泳道）——ELF 拖车，loader 忽略
    尾部数据；确定性 seed。

    仅 ELF 产物调用本函数；--link-mode objects 止步于 .o（无链接产物，
    平铺 stub 非 ELF，ai-decoy/seal 不适用）——objects 分支不触达此处。"""
    g = guards_list(args)
    if "arp" in g:
        # arp 拖车最先追加（ai-decoy 之前）→ seal 封印哈希覆盖 arp 块
        # （拖车被剥离/篡改 → seal 失配 → poison → arp 发射——V8-b 链）
        import guard_anti_reverse_prompt as _ARP
        desc = _ARP.apply_arp_notice(out_abs, arp_seed(args),
                                     args.arp_owner or "", args.arp_notice)
        print(f"protect: arp notice planted ({desc['trailer_bytes']} "
              f"trailer bytes, notice={desc['notice_id']}, "
              f"seed={desc['seed']})", file=sys.stderr)
    if "ai-decoy" in g:
        import guard_ai_decoy
        seed = args.guard_seed if args.guard_seed is not None \
            else random.randrange(1 << 30)
        desc = guard_ai_decoy.apply_ai_decoy(out_abs, seed)
        print(f"protect: ai-decoy planted ({desc['payloads']} payloads, "
              f"{desc['trailer_bytes']} trailer bytes, seed={seed})",
              file=sys.stderr)
    if "seal" in g:
        import hashlib
        import struct
        data = open(out_abs, "rb").read()
        hlen = len(data)
        digest = hashlib.sha256(data).digest()
        block = (struct.pack(">Q", hlen) + digest
                 + b"SEALBLA1")
        with open(out_abs, "ab") as f:
            f.write(block)
        print(f"protect: file seal applied (hashed {hlen} bytes, "
              f"digest {digest.hex()[:16]}...)", file=sys.stderr)


def run_multi(args, workdir, out_abs):
    """多函数模式（引擎 whibo 形态）：33 plans → 零训练模块权重 →
    模块 profile + 票号 manifest → 每函数一 TU 的运行时（共享权重数组 +
    模块状态）→ --multi 插桩 → 编译链接。

    阶段序对齐引擎六阶段 Full builder 的自研复刻；arch/权重/profile
    全部现场生成（t2 金标准 npz/profile 输入仅单函数模式使用）。
    """
    wd = workdir
    plan_path = os.path.join(wd, "module_plan.json")
    # ② 计划编译（A1 多函数：action 索引按函数独立从 0 重启）
    py("plan_compiler.py", os.path.join(wd, "input.ll"),
       "--functions", args.functions,
       "--module-identifier", args.source_path or os.path.join(wd, "input.ll"),
       "-o", plan_path)
    # ②.5 circuit-under-NN（circuit_v1 XOR 秘密共享 → 计划级 share 域变换；
    #     内置差分验证 live-out/STORE 逐位一致，失败即中止）
    #     antireverse v0.2 硬化模式：--nonce-mask（consumer_fused_v1 运行时
    #     nonce 派生掩码）/ --share-encode（stateful_v34 per-share 编码）
    if xor_mask_active(args):
        seed = args.guard_seed if args.guard_seed is not None \
            else random.randrange(1 << 30)
        cmd = ["circuit_share.py", plan_path, "-o", plan_path,
               "--shares", str(args.xor_shares), "--seed", str(seed),
               "--arith", args.xor_arith]
        if nonce_mask_active(args):
            cmd.append("--nonce-mask")
        if share_encode_active(args):
            cmd.append("--share-encode")
        if args.xor_functions:
            cmd += ["--functions", args.xor_functions]
        py(*cmd)
        lanes = ["xor-mask"]
        if nonce_mask_active(args):
            lanes.append("nonce-mask")
        if share_encode_active(args):
            lanes.append("share-encode")
        print(f"protect: circuit {'+'.join(lanes)} applied "
              f"(shares={args.xor_shares}, arith={args.xor_arith}, "
              f"seed={seed})", file=sys.stderr)
    plans = json.load(open(plan_path))["plans"]
    if not any(p["regions"] for p in plans):
        # 原生直通（镜像引擎行为）——守卫仍然生效：anti-emu/integrity 施加于
        # input.ll 副本 → transformed.ll，deny-attach 一并编入
        shutil.copyfile(os.path.join(wd, "input.ll"),
                        os.path.join(wd, "transformed.ll"))
        apply_guards_step(args, wd, "transformed.ll")
        # arp 直通：无 runtime TU → 语料无潜码（boot 期 memcpy 降级）
        arp_gen(args, wd)
        if chame_active(args):
            # 无可保护区域 → 无折叠落点（规格 §2.2：泳道降级为无操作；
            # 无 runtime TU → guard 单元不带 chame 引用，链接可解析）
            print("protect: CHAME lanes skipped — no protected regions "
                  "(native passthrough has no fold points)", file=sys.stderr)
        cc = "/dist/bin/clang " + " ".join(RT_FLAGS)
        gcc, gobj = guard_cc_parts(args, cc, chame=False)
        script = (f"{gcc}"
                  f"{cc} -c -x ir /w/transformed.ll -o /w/transformed.o &&\n"
                  f"/dist/bin/clang /w/transformed.o {gobj}-lm -s "
                  f"-o /w/protected_bin")
        docker_sh(script, wd, args)
        shutil.copyfile(os.path.join(wd, "protected_bin"), out_abs)
        os.chmod(out_abs, 0o755)
        apply_post_link_guards(args, out_abs)
        print("protect: no supported instructions — native passthrough",
              file=sys.stderr)
        print(f"protect: wrote {out_abs}", file=sys.stderr)
        return
    # ③ 零训练模块权重（D1/E：>1 plans 自动走 compose_module；
    #    --module 强制——单函数经 xor-mask 变换后须走通用模块路径；
    #    npz 级 rollout 全步验证）
    weights_npz = os.path.join(wd, "weights.npz")
    arch_json = os.path.join(wd, "arch.json")
    py("weight_composer.py", "--plan", plan_path, "--module",
       "--out", weights_npz, "--arch-out", arch_json)
    # ③.5 arp build 侧（M0/M2）：语料 + 潜码表（与 runtime_codegen 同源
    #     npz——codec 权重一致，decode walk roundtrip 成立）
    arp_gen(args, wd, weights_npz)
    # ④ 模块 profile + 票号 manifest（--module 同上强制；多函数自动）
    profile_json = os.path.join(wd, "profile.json")
    tickets_json = os.path.join(wd, "tickets.json")
    py(os.path.join("sprint_e", "profile_gen.py"),
       "--ll", os.path.join(wd, "input.ll"), "--plan", plan_path,
       "--module",
       "--arch", arch_json, "--out", profile_json,
       "--tickets", tickets_json)
    # ④.5 CHAME M6 标定（chame-oracle 开时现场标定 DIV-flags 期望，
    #     规格 §4.6/V12a——asm 形态与运行时探针逐字节一致 → 干净 delta=0）
    args._oracle_divflags = None
    if "chame-oracle" in chame_lanes(args):
        args._oracle_divflags = calibrate_oracle(args, wd)
        print(f"protect: chame-oracle calibrated (divflags="
              f"0x{args._oracle_divflags:x})", file=sys.stderr)
    # ⑤ 运行时生成（A2 模块模式：每函数一 TU + 共享 weights/state）
    #     chame 泳道开 → --guard-evidence（路由 A commit 形态 + CHAME 证据单元）
    #     arp 泳道开 → --arp-codes（owner TU 潜码表 + decode walk）
    rt_dir = os.path.join(wd, "runtime")
    ev_args = ["--guard-evidence"] if chame_active(args) else []
    arp_args = (["--arp-codes", os.path.join(wd, "arp_codes.json")]
                if "arp" in guards_list(args) else [])
    py("runtime_codegen.py", "--weights", weights_npz,
       "--profile", profile_json, "--out", rt_dir, *ev_args, *arp_args)
    # ⑥ 边界插桩（B3 --multi：manifest 含每函数 tag + 票表）
    py("instrument_ll.py", os.path.join(wd, "input.ll"),
       "-o", os.path.join(wd, "transformed.ll"),
       "--multi", tickets_json,
       "--module-id", args.module_id)
    # ⑥.5 守卫（CHAMELEON 移植）：anti-emu/integrity 重写插桩后的
    # transformed.ll；deny-attach 拷 C 守卫单元进 workdir
    apply_guards_step(args, wd, "transformed.ll")
    # ⑦ 编译链接（docker：transformed.o + runtime/*.o 全量）
    # M2/D4 --link-mode objects：止步于 .o（transformed.o + runtime/*.o），
    # 不链 ELF、不拷产物——供外部链接接管（如 wbp 的 ld -T stub.lds）。
    # M2/D1 --stub-tu：runtime 编译加 freestanding 旗标组（模板宏
    # NNOBF_FREESTANDING 激活静态 arena/自带 libc 函数/die 语义）。
    cc = "/dist/bin/clang " + " ".join(RT_FLAGS)
    if getattr(args, "stub_tu", False):
        # M3 修正:-fvisibility=hidden —— nnobf_module_* 权重/状态符号默认
        # DEFAULT 可见性,-fPIC 下 clang 走 GOT(REX_GOTPCRELX);lld 在静态
        # 非 PIE 链接(wbp 的 ld -T stub.lds -static)会把 GOT 加载松弛成
        # 绝对立即数(add $weights,%rcx),而 stub 运行时装载到随机基址,
        # 绝对地址全部失效 → dense 层读权重即 SIGSEGV(stub+0x8b300)。
        # hidden 可见性使 clang 直发 RIP 相对 lea,无 GOT、无松弛空间。
        cc += (" -DNNOBF_FREESTANDING -fPIC -ffreestanding "
               "-fno-stack-protector -fvisibility=hidden")
    cc += guard_rt_def(args)
    gcc, gobj = guard_cc_parts(args, cc)
    if getattr(args, "link_mode", "elf") == "objects":
        if "ai-decoy" in guards_list(args):
            # objects 模式无链接产物（止步 .o），ELF 拖车无处可植——
            # 平铺 stub 的拖车由外部链接方在 ld 产出 .bin 后以
            # guard_ai_decoy.py --flat 追加（wbp-anansi-link build_stub.sh
            # ⑥ 步已内置；安全前提见 guard_ai_decoy.py docstring）
            print("protect: ai-decoy deferred — objects mode: external "
                  "linker appends flat trailer via "
                  "guard_ai_decoy.py --flat after ld", file=sys.stderr)
        if "arp" in guards_list(args):
            # 同上：arp 拖车由外部链接方以 guard_anti_reverse_prompt.py
            # <bin> --flat --seed <guard-seed> --owner <...> 追加；wbp
            # build_stub.sh 守卫对象清单需同步新增 guard_arp.o 一项
            print("protect: arp trailer deferred — objects mode: external "
                  "linker appends flat trailer via "
                  "guard_anti_reverse_prompt.py <bin> --flat after ld "
                  "(wbp guard object list must add guard_arp.o)",
                  file=sys.stderr)
        if "chame-textkey" in chame_lanes(args):
            # 规格 §4.3/D5：平铺 stub 无 protect.py 最终链接产物、期望常量
            # 无回填点 → 自动跳过（fail-open：len==~0ull → 运行时无操作）
            print("protect: chame-textkey skipped — objects mode (flat "
                  "stub has no link product to backfill; lane degrades "
                  "to no-op, spec D5)", file=sys.stderr)
        script = (
            f"{gcc}"
            f"{cc} -c -x ir /w/transformed.ll -o /w/transformed.o &&\n"
            f"for f in /w/runtime/*.c; do\n"
            f"  {cc} -c -x c $f -o $(dirname $f)/$(basename $f .c).o "
            f"|| exit 1\n"
            f"done"
        )
        docker_sh(script, wd, args)
        print(f"protect: objects mode — transformed.o + runtime/*.o "
              f"ready in {wd} ({len(plans)} functions)", file=sys.stderr)
        return
    # chame-textkey 开 → 链接去 -s（回填需 symtab 定位三联/窗口；回填后
    # Python 侧 strip 恢复基线——规格 §4.3 post-link 回填）
    need_tk = "chame-textkey" in chame_lanes(args)
    strip_flag = "" if need_tk else "-s "
    script = (
        f"{gcc}"
        f"{cc} -c -x ir /w/transformed.ll -o /w/transformed.o &&\n"
        f"for f in /w/runtime/*.c; do\n"
        f"  {cc} -c -x c $f -o $(dirname $f)/$(basename $f .c).o "
        f"|| exit 1\n"
        f"done &&\n"
        f"/dist/bin/clang /w/transformed.o /w/runtime/*.o {gobj}-lm "
        f"{strip_flag}-o /w/protected_bin"
    )
    docker_sh(script, wd, args)
    if need_tk:
        tk = apply_textkey_backfill(args, os.path.join(wd, "protected_bin"),
                                    wd)
        print(f"protect: chame-textkey backfilled (window={tk['window_bytes']}"
              f"B, {tk['slices']} slices, expect={tk['expect']})", file=sys.stderr)
    shutil.copyfile(os.path.join(wd, "protected_bin"), out_abs)
    os.chmod(out_abs, 0o755)
    apply_post_link_guards(args, out_abs)
    if chame_active(args):
        lanes = chame_lanes(args)
        print(f"protect: CHAME lanes active {lanes} "
              f"(strict={'on' if args.guard_strict else 'off'}, "
              f"route_b={'xor-mask' if xor_mask_active(args) else 'off'})",
              file=sys.stderr)
    print(f"protect: wrote {out_abs} "
          f"({len(plans)} functions, module mode)", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="ANANSI 自研保护管线（B1）")
    ap.add_argument("--source", required=True)
    ap.add_argument("--output", required=True, help="输出受保护二进制路径")
    ap.add_argument("--weight-npz",
                    default=os.path.join(ROOT, "weights", "modules",
                                         "module_weights_t2_fp32.npz"))
    ap.add_argument("--profile",
                    default=os.path.join(HERE, "runtime_codegen_data",
                                        "profile_fp32_t2.json"))
    ap.add_argument("--ticket-table", default=None,
                    help="票号表 JSON 文件（region→u64）；缺省取 profile 的 "
                         "boundary_cases 票号")
    ap.add_argument("--tickets", default=None,
                    help="票号表 JSON 内联（与 --ticket-table 二选一）")
    ap.add_argument("--frontend", choices=["neural", "raw"], default="neural",
                    help="前端档案：neural=轮2 纯神经（默认）；raw=轮1 集成"
                         "保护全旗标+归一化（其计划与轮2 权重不匹配时会因"
                         "契约断言中止）")
    ap.add_argument("--region-gaps", action="store_true",
                    help="任务 E：相邻区域间插入哑索引（周期微程序 q 行"
                         "折叠；入口态经 region_q[start] 重载）")
    ap.add_argument("--workdir", default=None)
    ap.add_argument("--module-id", default="/w/input.ll",
                    help="transformed.ll 的 ModuleID（引擎为临时 input.ll 路径）")
    ap.add_argument("--function", default="main")
    ap.add_argument("--native-call-gate", default=None,
                    help="Opt-in direct-call barrier: comma-separated entry roots; "
                         "gate their defined native descendants. No nonlocal exits.")
    ap.add_argument("--functions", default=None,
                    help="多函数模式：逗号分隔清单或 @file → 33 函数"
                         " whibo 形态（单 module 多 plans；引擎对齐："
                         "action 索引按函数独立从 0 重启）")
    ap.add_argument("--source-path", default=None,
                    help="多函数模式源码容器路径（引擎真值 /whibo/"
                         "harness_42.c；缺省 /w/<src>）")
    ap.add_argument("--cflag", action="append", default=None,
                    help="前端透传旗标（可重复，原样附加）")
    ap.add_argument("--include", action="append", default=None,
                    help="-I 路径（可重复；宿主存在的目录自动挂载到"
                         "同名容器路径）")
    ap.add_argument("--define", action="append", default=None,
                    help="-D 定义（可重复，如 _GNU_SOURCE）")
    ap.add_argument("--mount", action="append", default=None,
                    help="docker 额外挂载 HOST:CONT（可重复）")
    ap.add_argument("--native", action="store_true",
                    help="原生执行（README 官方 docker 替代）：本机即 "
                         "linux/amd64 时直接宿主 sh 运行各阶段，/dist、/w "
                         "按宿主真实路径展开；--include/--source-path 传宿主"
                         "路径")
    ap.add_argument("--stub-tu", action="store_true",
                    help="M2/D1 stub TU 模式：前端对齐 wbp stub 构建"
                         "（-fPIC -ffreestanding -fno-stack-protector "
                         "-fno-jump-tables -DWBP_ARCH_X86_64），runtime "
                         "编译加 -DNNOBF_FREESTANDING（模板静态 arena/"
                         "自带 libc 函数/SIGSEGV die 语义）")
    ap.add_argument("--link-mode", choices=["elf", "objects"], default="elf",
                    help="M2/D4：objects=止步于 transformed.o + runtime/*.o"
                         "（供外部链接接管，如 wbp stub 的 ld -T stub.lds）；"
                         "elf=默认完整可执行")
    ap.add_argument("--guards",
                    default=("anti-emu,integrity,deny-attach,churn,opaque,"
                             "ai-decoy,seal"),
                    help="守护集（v0.1.1-antidebug-bal 六泳道，默认全开）："
                         "anti-emu=CHAMELEON cpuid 双读折叠（M1：信号 3→7）；"
                         "integrity=分布式互证守卫；deny-attach=TracerPid 反"
                         "调试；churn=影子堆搅动（防内存差分）；opaque=数论"
                         "不透明谓词；ai-decoy=ELF 拖车诱饵（仅 ELF 产物，"
                         "objects 模式不适用；置空字符串关闭全部）；xor-mask="
                         "circuit-under-NN 泳道（circuit_v1 XOR 秘密共享移植"
                         "为计划级 share 域变换，share 运算全部由神经核心执行"
                         "——配 --xor-shares/--xor-arith/--xor-functions，默认"
                         "关）；nonce-mask=antireverse v0.2 泳道"
                         "（consumer_fused_v1 运行时 nonce 派生掩码：split/"
                         "刷新掩码运行期由区域 integer live-in 混合派生，"
                         "不再是计划常量——掩码静态提取失效，默认关，蕴含"
                         "xor-mask）；share-encode=antireverse v0.2 泳道"
                         "（stateful_v34 per-share 独立编码：槽位驻留 share "
                         "以 rot+salt+additive 编码，参数 seed 派生，约 +2x "
                         "share 步，默认关，蕴含 xor-mask；masked 档不建议"
                         "叠加）；CHAMÆLEON M1-M6 反调试泳道（chame-antidebug "
                         "v0.2，默认关，配 --guard-strict/--guard-seed）："
                         "chame-tracer=M2 TracerPid 运行期轮询；chame-"
                         "textkey=M3 .text 折哈希即密钥（ELF 完整、平铺 "
                         "stub 自动跳过）；chame-hwbp=M4 fork self-debugger "
                         "读 DR7；chame-trap=M5 SIGTRAP 处理器即密钥；"
                         "chame-oracle=M6 x86 一致性 oracle；arp=anti-reverse-"
                         "prompt 声明式守卫（v0.1 opt-in，设计文档 anti-"
                         "reverse-prompt_v0.0.md：文件 ARPNOTC1 拖车+.rodata/"
                         "内存 NN 物化缓冲/stderr 证据命中发射三层植入"
                         "拒绝逆向声明（TRUSTED_ACCESS_REQUIRED），guard "
                         "逻辑受 NN 保护——潜码表烤入 owner TU + decode "
                         "walk 物化；配 --arp-owner/--arp-notice，emit "
                         "契约=干净零输出、绝不 exit、绝不写 stdout）")
    ap.add_argument("--arp-owner", default="",
                    help="arp 泳道权利人字段（真实权利人；缺省 the "
                         "copyright holder——伦理红线：不虚构法律地位，见 "
                         "anti-reverse-prompt_v0.0.md §4.6）")
    ap.add_argument("--arp-notice", default=None,
                    help="arp 自定义 FULL 声明文本（UTF-8 文件，占位符 "
                         "{NOTICE_ID}/{OWNER}/{DATE}/{SHA256} 可选；缺省"
                         "双语模板）")
    ap.add_argument("--guard-seed", type=int, default=None,
                    help="守卫构建种子（缺省每构建随机；同种子可复现；"
                         "xor-mask/chame 泳道复用该种子）")
    ap.add_argument("--guard-strict", action="store_true",
                    help="CHAMÆLEON M1-M6 严格模式（规格 D4）：任一 chame "
                         "泳道证据命中（__sdk_ev != 0）升级为 exit 173"
                         "（复用 deny-attach 拒绝码），默认关=静默折叠")
    ap.add_argument("--xor-shares", type=int, default=2, choices=[2, 4, 8],
                    help="xor-mask 泳道 share 数（2/4/8，默认 2；体积随 "
                         "share 数与 --xor-arith 策略增长）")
    ap.add_argument("--xor-arith", choices=["fold", "masked"],
                    default="fold",
                    help="xor-mask 的 ADD/SUB 策略：fold=折叠输入→明文原"
                         "步骤→再拆分（默认，wbp 规模适用）；masked="
                         "circuit_v1 Kogge-Stone 掩码进位加法器（全 share "
                         "域，步数 ~x200，仅小样例）")
    ap.add_argument("--xor-functions", default=None,
                    help="xor-mask 仅变换这些函数（逗号分隔或 @file；缺省"
                         "全部——大函数集超 4096 动作类上限时可用此收窄）")
    ap.add_argument("--dist",
                    default=os.path.expanduser(
                        "~/Downloads/anansi-linux-20261022-x86_64"))
    ap.add_argument("--image", default="anansi-verify-amd64")
    args = ap.parse_args()
    # antireverse v0.2 归一化：nonce-mask / share-encode 蕴含 xor-mask
    # （二者是 xor-mask 变换的硬化模式；显式补全一次，后续 guards_list 一致）
    _g = guards_list(args)
    if ("nonce-mask" in _g or "share-encode" in _g) \
            and "xor-mask" not in _g:
        _g.append("xor-mask")
        args.guards = ",".join(_g)
        print("protect: nonce-mask/share-encode implies xor-mask "
              "(guard list normalized)", file=sys.stderr)

    out_abs = os.path.abspath(args.output)
    workdir = args.workdir or out_abs + ".build"
    os.makedirs(workdir, exist_ok=True)
    src_name = os.path.basename(args.source)
    shutil.copyfile(args.source, os.path.join(workdir, src_name))

    # xor-mask（circuit-under-NN）：单函数模式改走多函数机制（计划变换后
    # 槽位/步数与 t2 金标准 npz/profile 不再匹配，需现场组装权重+profile）；
    # 须在前端之前重定向——多函数档案含 -fno-inline（区域身份）
    if args.functions is None and xor_mask_active(args):
        args.functions = args.function
        print(f"protect: xor-mask active — single function '{args.function}' "
              f"routed through module pipeline (weights/profile composed "
              f"on the fly)", file=sys.stderr)

    # ① 前端
    run_frontend(args, workdir, src_name)

    if args.functions:
        run_multi(args, workdir, out_abs)
        return

    # ---- 单函数模式：t2 金标准 profile / 票表输入（多函数模式现场生成）----
    profile = json.load(open(args.profile))
    if args.tickets:
        tickets = {str(k): int(v) for k, v in json.loads(args.tickets).items()}
    elif args.ticket_table:
        tickets = {str(k): int(v) for k, v in
                   json.load(open(args.ticket_table)).items()}
    else:
        tickets = {str(i): int(c["ticket"])
                   for i, c in enumerate(profile["boundary_cases"])}
    tag = profile["tags"]["TAG_IR"]
    tickets_path = os.path.join(workdir, "tickets.json")
    json.dump(tickets, open(tickets_path, "w"), indent=1)

    # ② 计划编译（A1）
    py("plan_compiler.py", os.path.join(workdir, "input.ll"),
       "--function", args.function,
       "--module-identifier", os.path.join(workdir, "input.ll"),
       "-o", os.path.join(workdir, "module_plan.json"),
       *(["--region-gaps"] if args.region_gaps else []))
    plan0 = json.load(open(os.path.join(workdir, "module_plan.json")))["plans"][0]
    if not plan0["regions"]:
        # 无可保护指令：镜像引擎 no-supported-instructions 行为 →
        # 原生直通（不插桩、不链神经运行时）——守卫仍生效
        shutil.copyfile(os.path.join(workdir, "input.ll"),
                        os.path.join(workdir, "transformed.ll"))
        apply_guards_step(args, workdir, "transformed.ll")
        # arp 直通：无 runtime TU → 语料无潜码（boot 期 memcpy 降级）
        arp_gen(args, workdir)
        if chame_active(args):
            # 无可保护区域 → 无折叠落点（规格 §2.2：泳道降级为无操作；
            # 无 runtime TU → guard 单元不带 chame 引用，链接可解析）
            print("protect: CHAME lanes skipped — no protected regions "
                  "(native passthrough has no fold points)", file=sys.stderr)
        cc = "/dist/bin/clang " + " ".join(RT_FLAGS)
        gcc, gobj = guard_cc_parts(args, cc, chame=False)
        script = (f"{gcc}"
                  f"{cc} -c -x ir /w/transformed.ll -o /w/transformed.o &&\n"
                  f"/dist/bin/clang /w/transformed.o {gobj}-lm -s "
                  f"-o /w/protected_bin")
        docker_sh(script, workdir, args)
        shutil.copyfile(os.path.join(workdir, "protected_bin"), out_abs)
        os.chmod(out_abs, 0o755)
        apply_post_link_guards(args, out_abs)
        print("protect: no supported instructions — native passthrough",
              file=sys.stderr)
        print(f"protect: wrote {out_abs}", file=sys.stderr)
        return
    # 契约断言：派生计划 ↔ 运行时 profile
    check_plan_profile(workdir, profile, tickets,
                       region_gaps=args.region_gaps)
    # ②.6 CHAME M6 标定（chame-oracle 开时现场标定 DIV-flags 期望，
    #     规格 §4.6/V12a——asm 形态与运行时探针逐字节一致 → 干净 delta=0；
    #     须先于 runtime 编译，-DNNOBF_ORACLE_DIVFLAGS 由 guard_rt_def 注入）
    args._oracle_divflags = None
    if "chame-oracle" in chame_lanes(args):
        args._oracle_divflags = calibrate_oracle(args, workdir)
        print(f"protect: chame-oracle calibrated (divflags="
              f"0x{args._oracle_divflags:x})", file=sys.stderr)
    # ②.8 arp build 侧（M0/M2）：语料 + 潜码表（与 runtime_codegen 同源
    #     npz——codec 权重一致，decode walk roundtrip 成立）
    arp_gen(args, workdir, args.weight_npz)
    # ③ 运行时生成（A2）——chame 泳道开 → --guard-evidence（路由 A commit
    #     形态 + CHAME 证据单元；关闭时发射基线形态，产物零扰动）；
    #     arp 泳道开 → --arp-codes（owner TU 潜码表 + decode walk）
    rt_dir = os.path.join(workdir, "runtime")
    ev_args = ["--guard-evidence"] if chame_active(args) else []
    arp_args = (["--arp-codes", os.path.join(workdir, "arp_codes.json")]
                if "arp" in guards_list(args) else [])
    py("runtime_codegen.py", "--weights", args.weight_npz,
       "--profile", args.profile, "--out", rt_dir, *ev_args, *arp_args)
    # ④ 边界插桩（B3）
    py("instrument_ll.py", os.path.join(workdir, "input.ll"),
       "-o", os.path.join(workdir, "transformed.ll"),
       "--tag", tag, "--tickets-file", tickets_path,
       "--module-id", args.module_id, "--function", args.function)
    # ④.5 守卫（CHAMELEON 移植）：anti-emu/integrity 重写插桩后的
    # transformed.ll；deny-attach 拷 C 守卫单元进 workdir
    apply_guards_step(args, workdir, "transformed.ll")
    # ⑤ 编译链接（docker，引擎 target_reach 实测旗标）
    #     chame-textkey 开 → 链接去 -s（回填需 symtab 定位三联/窗口；
    #     回填后 Python 侧 strip 恢复基线——规格 §4.3 post-link 回填）
    cc = "/dist/bin/clang " + " ".join(RT_FLAGS)
    cc += guard_rt_def(args)
    gcc, gobj = guard_cc_parts(args, cc)
    need_tk = "chame-textkey" in chame_lanes(args)
    strip_flag = "" if need_tk else "-s "
    script = (
        f"{gcc}"
        f"{cc} -c -x ir /w/transformed.ll -o /w/transformed.o &&\n"
        f"{cc} -c -x c /w/runtime/runtime_0_main.c -o /w/runtime_0.o &&\n"
        f"{cc} -c -x c /w/runtime/runtime_weights.c -o /w/runtime_1.o &&\n"
        f"{cc} -c -x c /w/runtime/runtime_module_state.c -o /w/runtime_2.o &&\n"
        f"/dist/bin/clang /w/transformed.o /w/runtime_0.o /w/runtime_1.o "
        f"/w/runtime_2.o {gobj}-lm {strip_flag}-o /w/protected_bin"
    )
    docker_sh(script, workdir, args)
    if need_tk:
        tk = apply_textkey_backfill(args, os.path.join(workdir, "protected_bin"),
                                    workdir)
        print(f"protect: chame-textkey backfilled (window={tk['window_bytes']}"
              f"B, {tk['slices']} slices, expect={tk['expect']})", file=sys.stderr)
    shutil.copyfile(os.path.join(workdir, "protected_bin"), out_abs)
    os.chmod(out_abs, 0o755)
    apply_post_link_guards(args, out_abs)
    if chame_active(args):
        lanes = chame_lanes(args)
        print(f"protect: CHAME lanes active {lanes} "
              f"(strict={'on' if args.guard_strict else 'off'}, "
              f"route_b={'xor-mask' if xor_mask_active(args) else 'off'})",
              file=sys.stderr)
    print(f"protect: wrote {out_abs}", file=sys.stderr)


if __name__ == "__main__":
    main()

