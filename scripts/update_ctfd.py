#!/usr/bin/python3.8

import shutil
import json
import re
import os

def mkdir_lazy(dirpath):
    if os.path.isdir(dirpath):
        return
    os.mkdir(dirpath)

def read_challenges():
    with open("stages.json", "r") as f:
        stages_conf = json.load(f)
    num_bleichenbacher_challenges = 0
    for stage in stages_conf:
        if stage[2] == "PKCS_1_5":
            num_bleichenbacher_challenges += 1
    with open("CTFd/db/challenges.json", "r") as f:
        challenges = json.load(f)
    challenge_dict = {}
    for challenge in challenges['results']:
        if challenge['category'] not in ("Bleichenbacher", "Manger"):
            raise ValueError("Invalid challenge category: " + challenge['category'])
        base = 0 if challenge['category'] == "Bleichenbacher" else num_bleichenbacher_challenges
        try:
            challenge_num = int(re.findall("^Challenge ([0-9]+)$", challenge['name'])[0])
        except IndexError:
            raise ValueError("Found a challenge name not matching 'Challenge <num>': " + challenge['name'])
        challenge_dict[challenge['id']] = challenge_num
        with open(os.path.join("ctf", "stage_%02d" % challenge_num, "port"), "r") as f:
            port = f.read()
        challenge['connection_info'] = "Port: " + port
    with open("CTFd/db/challenges.json", "w") as f:
        json.dump(challenges, f)
    return challenge_dict

def update_files(challenges):
    mkdir_lazy(os.path.join("CTFd", "uploads"))
    with open("CTFd/db/files.json", "r") as f:
        files = json.load(f)['results']
    for f in files:
        loc = f['location']
        try:
            dirname, stagenum = re.findall("^([0-9a-f]+)/stage_([0-9]+)\.zip$", loc)[0]
        except IndexError:
            raise ValueError("Found a file location not matching stage_<num>.zip: " + loc)
        mkdir_lazy(os.path.join("CTFd", "uploads", dirname))
        stagenum = int(stagenum)
        stage_name = "stage_%02d" % stagenum
        shutil.copyfile(os.path.join("ctf", stage_name, stage_name + ".zip"),
                        os.path.join("CTFd", "uploads", dirname, stage_name + ".zip"))

def update_flags(challenges):
    with open("CTFd/db/flags.json", "r") as f:
        flags = json.load(f)
    for flag in flags['results']:
        challenge_num = challenges[flag['challenge_id']]
        with open(os.path.join("ctf", "stage_%02d" % challenge_num, "flag"), "r") as f:
            flag_val = f.read()
        flag['content'] = flag_val
    with open("CTFd/db/flags.json", "w") as f:
        json.dump(flags, f)

def main():
    challenges = read_challenges()
    update_files(challenges)
    update_flags(challenges)

if __name__ == "__main__":
    main()
