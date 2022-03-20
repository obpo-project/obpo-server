# Author: hluwa <hluwa888@gmail.com>
# HomePage: https://github.com/hluwa
# CreateTime: 2022/3/8
import base64
import json
import logging

from idaapi import *
from idc import *
from obpo.analysis.dispatcher import DispatchAnalyzer
from obpo.analysis.pathfinder import FlowFinder
from obpo.patch.deoptimizer import SplitCommonPatcher
from obpo.patch.link import FlowPatcher

seg_class = {SEG_CODE: "CODE",
             SEG_DATA: "DATA",
             SEG_BSS: "BSS",
             SEG_XTRN: "XTRN",
             SEG_COMM: "COMM",
             SEG_ABSSYM: "ABS"}


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
        for ea in funcs:
            start = int(ea)
            end = start + len(funcs[ea])
            hf = hexrays_failure_t()
            mbr.ranges.push_back(range_t(start, end))
        ml = mlist_t()
        mba = gen_microcode(mbr, hf, ml, DECOMP_WARNINGS, level)
        x.append(mba)
    except:
        pass
    try:
        for ea in funcs:
            try:
                x.append(decompile(int(ea)))
            except:
                pass
    except:
        pass
    return x


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


def prepare():
    task_path = ARGV[1]
    task = open(task_path).read()
    task = json.loads(task)
    create_segments(task["segments"])
    create_func(task["func"], task["t"])
    return task


def main():
    task_path = ARGV[1]
    debug_mode(os.path.join(os.path.dirname(task_path), "log.txt"))
    task = prepare()
    x = prepare_mc(task["func"], task["maturity"])
    mba: mba_t = mba_t_deserialize(base64.b64decode(task['mba']))
    analyzer = DispatchAnalyzer(mba=mba)
    for ea in task["dispatchers"]:
        try:
            analyzer.mark_dispatcher(ea)
        except:
            pass
    analyzer.run()
    finder = FlowFinder(analyzer)
    finder.run()
    SplitCommonPatcher(finder).run()
    patcher = FlowPatcher(analyzer)
    for edge, flows in finder.edge4flows().items():
        patcher.run(edge, flows)
    for b in visit_blocks(mba):
        if b.type in [BLT_STOP, BLT_XTRN] or b.serial == 0: continue
        b.type = BLT_NONE
        b.mark_lists_dirty()
    result = base64.b64encode(mba.serialize())
    with open(os.path.join(os.path.dirname(task_path), "result"), "w") as out:
        out.write(result.decode())
    return mba


auto_wait()
mba = main()
exit()
