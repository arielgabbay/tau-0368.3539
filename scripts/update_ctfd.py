#!/usr/bin/python3.8

import shutil
import json
import re
import os
from stage_conf import read_stages_conf

def mkdir_lazy(dirpath):
    if os.path.isdir(dirpath):
        return
    os.mkdir(dirpath)

def update_challenges(stages):
    num_bleichenbacher_challenges = 0
    with open("CTFd_export/db/challenges.json", "r") as f:
        challenges = json.load(f)
    challenge_dict = {}
    for challenge in challenges['results']:
        if challenge['category'] not in stages:
            raise ValueError("Invalid challenge category: " + challenge['category'])
        for i, stage in enumerate(stages[challenge['category']]):
            stage_num = i + 1
            if stage.name == challenge['name']:
                challenge_dict[challenge['id']] = (stage_num, stage)
                break
        else:
            raise AssertionError("Couldn't find a stage under category %s with name %s" % (category, challenge['name']))
        with open(os.path.join("ctf", challenge['category'], "stage_%02d" % stage_num, "port"), "r") as f:
            port = f.read()
        challenge['connection_info'] = "Port: " + port
    with open("CTFd_export/db/challenges.json", "w") as f:
        json.dump(challenges, f)
    return challenge_dict

def update_files(challenges):
    mkdir_lazy(os.path.join("CTFd_export", "uploads"))
    with open("CTFd_export/db/files.json", "r") as f:
        files = json.load(f)['results']
    for f in files:
        loc = f['location']
        chal_id = f['challenge_id']
        if os.path.basename(loc) == "files.zip":
            dirname = os.path.dirname(loc)
        else:
            continue
        mkdir_lazy(os.path.join("CTFd_export", "uploads", dirname))

        stage_num, stage = challenges[chal_id]
        src = os.path.join("ctf", stage.category, "stage_%02d" % stage_num, "files.zip")
        dst = os.path.join("CTFd_export", "uploads", dirname, "files.zip")
        shutil.copyfile(src, dst)

def main():
    stages = read_stages_conf("stages.json")
    challenges = update_challenges(stages)
    update_files(challenges)

if __name__ == "__main__":
    main()
