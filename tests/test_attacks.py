import os
import pytest
import json
import subprocess
import itertools

PARALLEL_STAGES = {2, 4, 6, 8}
STAGE_TIMES = [10, 10, 10, 10, 15, 10, 2, 2]
ATTACK_SCRIPTS = {
    "PKCS_1_5": "bleichenbacher.py",
    "PKCS_OAEP": "manger.py"
}

CTF_DIR = "ctf"
ATTACK_SCRIPT_DIR = "attack_scripts"

class StageInfo:
    def __init__(self, stage_num, stagedir, group_masks, stage_conf):
        with open(os.path.join(stagedir, "flag"), "r") as f:
            self.flag = f.read()
        with open(os.path.join(stagedir, "port"), "r") as f:
            self.port = int(f.read())
        self.ports = [self.port ^ mask for mask in group_masks]
        self.raw_conf = stage_conf[:]
        self.attack_script = os.path.join(ATTACK_SCRIPT_DIR, ATTACK_SCRIPTS[self.raw_conf[2]])
        self.num_processes = self.raw_conf[1] if stage_num in PARALLEL_STAGES else 1
        self.timeout = STAGE_TIMES[stage_num - 1]

class CTFInfo:
    def __init__(self, ctfdir):
        self.group_masks = []
        with open(os.path.join(ctfdir, "group_masks"), "r") as f:
            for l in f.readlines():
                self.group_masks.append(int(l))
        with open("stages.json", "r") as f:
            stages_conf = json.load(f)
        self.stages = []
        num_stages = len([n for n in next(os.walk(ctfdir))[1] if n.startswith("stage_")])
        for stage_num in range(1, num_stages + 1):
            self.stages.append(StageInfo(stage_num, os.path.join(ctfdir, "stage_%02d" % stage_num),
                                         self.group_masks, stages_conf[stage_num - 1]))


ctf_info = CTFInfo(CTF_DIR)

stage_nums = list(range(1, len(ctf_info.stages) + 1))
group_nums = list(range(1, len(ctf_info.group_masks) + 1))
test_params = list(itertools.product(stage_nums, group_nums))

@pytest.mark.parametrize("stage_num,group_num", test_params)
def test_stage(stage_num, group_num):
    stage = ctf_info.stages[stage_num - 1]
    enc_file = os.path.join(CTF_DIR, "stage_%02d" % stage_num, "group", "enc.bin")
    key_file = os.path.join(CTF_DIR, "stage_%02d" % stage_num, "group", "pubkey.bin")
    sp = subprocess.Popen(["python3.8", stage.attack_script, "-s", "127.0.0.1", "-c", enc_file, "-k",
                           key_file, "-l", "1024", "-g", str(stage_num), "-n",
                           str(stage.num_processes), "-p", str(stage.ports[group_num - 1])],
                          stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    errval = sp.wait(timeout=60 * stage.timeout)
    assert errval == 0, ("Attack returned %d:\n" % errval) + sp.stderr.read().decode()
    if stage.attack_script.endswith("bleichenbacher.py"):
        stdout = sp.stdout.read().decode()
        last_line = stdout.splitlines()[-1].strip()
        assert last_line == stage.flag, "Attack returned different flag:\n" + stdout
