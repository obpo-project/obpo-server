# Author: hluwa <hluwa888@gmail.com>
# HomePage: https://github.com/hluwa
# CreateTime: 2022/3/8
import base64
import json
import logging

from idaapi import *
from idc import *
from obpo.analysis.dispatcher import DispatchAnalyzer
from obpo.analysis.pathfinder import FlowFinder, EmuPathFinder
from obpo.patch.deoptimizer import SplitCommonPatcher
from obpo.patch.link import FlowPatcher

TASK_PATH = ARGV[1]
TASK_DIR = os.path.dirname(TASK_PATH)


def _safe_call(f):
    try:
        return f()
    except:
        pass


def warning(s):
    with open(os.path.join(TASK_DIR, "warn"), 'a') as o:
        o.write(s + "\r\n")


def error(s):
    with open(os.path.join(TASK_DIR, "error"), 'a') as o:
        o.write(s + "\r\n")


def visit_blocks(mba: mba_t):
    for i in range(mba.qty):
        mblock = mba.get_mblock(i)
        yield mblock


def debug_mode(path):
    logger = logging.getLogger("OBPO")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.FileHandler(path))


def prepare_mc(funcs, level):
    x = []
    try:
        mbr = mba_ranges_t()
        hf = hexrays_failure_t()
        ml = mlist_t()
        for ea in funcs:
            start = int(ea)
            end = start + len(funcs[ea])
            mbr.ranges.push_back(range_t(start, end))
        mba = gen_microcode(mbr, hf, ml, DECOMP_WARNINGS, level)
        x.append(mba)
    except:
        pass
    for ea in funcs:
        x.append(_safe_call(lambda: decompile(int(ea))))
    return x


seg_class = {SEG_CODE: "CODE",
             SEG_DATA: "DATA",
             SEG_BSS: "BSS",
             SEG_XTRN: "XTRN",
             SEG_COMM: "COMM",
             SEG_ABSSYM: "ABS"}


def create_segments(segments):
    for seg in segments:
        sclass = seg["sclass"]
        sclass = seg_class[sclass] if sclass in seg_class else "UNK"
        add_segm(seg["para"], seg["start"], seg["end"], seg["name"], sclass)
        segm = getseg(seg["start"])
        set_segm_base(segm, seg["base"])
        set_segm_attr(segm.start_ea, SEGATTR_PERM, seg["perm"])
        set_segm_alignment(segm.start_ea, seg["align"])
        set_segm_type(segm.start_ea, seg["type"])
        if seg["addressing"]:
            set_segm_addressing(segm.start_ea, seg["addressing"])
        auto_wait()
        del_items(segm.start_ea)


def create_func(func_bytes, T):
    for ea in func_bytes:
        bs = base64.b64decode(func_bytes[ea])
        ea = int(ea)
        end = ea + len(bs)
        patch_bytes(ea, bs)
        del_items(ea)
        auto_wait()
        if ea in T:
            ea &= ~1
            split_sreg_range(ea, "T", 1, SR_user)
        auto_make_code(ea)
        auto_wait()
        add_func(ea, end)
        auto_wait()


def finder_hooks(finder):
    orig_explore = finder._finder_by_explore

    def explore_hook():
        incomplete = orig_explore()
        if incomplete:
            warning("explore is incomplete and uses aggressive exploration technology. \n"
                    "[!] note that the control flow may be wrong")
        return incomplete

    finder._finder_by_explore = explore_hook


def emufinder_hooks():
    orig_emufinder_run = EmuPathFinder.run

    def emufinder_run_hook(self):
        res = orig_emufinder_run(self)
        if not self.results:
            warning("cannot found succs for {}".format(hex(self.source.blk.start)))
        return res

    EmuPathFinder.run = emufinder_run_hook


def patcher_hooks(patcher):
    orig_run = patcher.run

    def run_hook(edge, flows):
        success = orig_run(edge, flows)
        if not success:
            _from = hex(edge.src.start)
            _to = {hex(flow.dest_block.start) for flow in flows}
            warning("cannot patch edges from {} to {}".format(_from, _to))
        return success

    patcher.run = run_hook


def prepare():
    task_path = ARGV[1]
    task = open(task_path).read()
    task = json.loads(task)
    create_segments(task["segments"])
    create_func(task["func"], task["t"])
    return task


def main():
    # Prepare environment for microcode
    debug_mode(os.path.join(TASK_DIR, "log.txt"))
    task = prepare()
    x = prepare_mc(task["func"], task["maturity"])  # save decompile references to avoid some crash
    mba: mba_t = mba_t_deserialize(base64.b64decode(task['mba']))
    if mba is None:
        error("load mba failed.")
        return

    # Dispatch Analysis
    analyzer = DispatchAnalyzer(mba=mba)
    for ea in task["dispatchers"]: analyzer.mark_dispatcher(ea)
    try:
        analyzer.run()
    except:
        error("cannot to analysis dispatcher")
        return

    # Real Control Flow Finder
    emufinder_hooks()
    finder = FlowFinder(analyzer)
    finder_hooks(finder)
    try:
        finder.run()
    except:
        logging.getLogger("OBPO").exception("exception in flow finder")
        warning("exception in flow finder, the control flow maybe wrong")

    # Recovering Control Flow Edges
    SplitCommonPatcher(finder).run()
    patcher = FlowPatcher(analyzer)
    patcher_hooks(patcher)
    try:
        for edge, flows in finder.edge4flows().items():
            patcher.run(edge, flows)
    except:
        logging.getLogger("OBPO").exception("exception in flow patcher")
        warning("exception in flow patcher, the code maybe not clean")

    # Clear graph to bypass verify mba
    for b in visit_blocks(mba):
        if b.type in [BLT_STOP, BLT_XTRN] or b.serial == 0: continue
        b.type = BLT_NONE
        b.mark_lists_dirty()

    result = base64.b64encode(mba.serialize())
    with open(os.path.join(os.path.dirname(TASK_PATH), "mba"), "w") as out:
        out.write(result.decode())
    return mba


auto_wait()
mba = main()
exit()
