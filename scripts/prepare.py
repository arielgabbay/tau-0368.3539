#!/usr/bin/python3.8
from Crypto.PublicKey import RSA
import Crypto.Cipher.PKCS1_v1_5 as PKCS_1_5
import Crypto.Cipher.PKCS1_OAEP as PKCS_OAEP
from distutils.dir_util import copy_tree
import random
import json
import os
import sys
import argparse
import shutil
import subprocess

class Stage:
    def __init__(self, servers_per_group, threads_per_server, pkcs_class, minqueries, maxqueries, servers_ip):
        self.servers_per_group = servers_per_group
        self.threads_per_server = threads_per_server
        self.pkcs_class = pkcs_class
        self.idx = 0 if pkcs_class == PKCS_1_5 else 1
        self.ports = None
        self.server_ports = []
        self.minqueries = minqueries
        self.maxqueries = maxqueries
        self.servers_ip = servers_ip

PKCS_CLASSES = {"PKCS_1_5": PKCS_1_5, "PKCS_OAEP": PKCS_OAEP}

def read_stages_conf(conf_filename):
    with open(conf_filename, "r") as f:
        conf = json.load(f)
    stages = []
    for spg, tps, pkcs_str, minqueries, maxqueries, servers_ip in conf:
        pkcs_class = PKCS_CLASSES[pkcs_str]
        stages.append(Stage(spg, tps, pkcs_class, minqueries, maxqueries, servers_ip))
    return stages

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-groups", "-n", required=True, type=int)
    parser.add_argument("--nginx-conf", "-c", required=True)
    parser.add_argument("--nginx-command", "-d", required=True)
    parser.add_argument("--servers-build-command", "-s", required=True)
    parser.add_argument("--servers-run-command", "-r", required=True)
    parser.add_argument("--stages-conf", "-g", required=True)
    parser.add_argument("--flag-pool-dir", "-f", required=True)
    parser.add_argument("ctf_dir")
    return parser.parse_args()

def get_flag(flags, used_flags, stage):
    for i, flag in enumerate(flags):
        if i in used_flags:
            continue
        if stage.minqueries <= flag[stage.idx] <= stage.maxqueries:
            used_flags.add(i)
            return i
    return None

def main():
    args = parse_args()
    stages = read_stages_conf(args.stages_conf)
    with open(os.path.join(args.flag_pool_dir, "queries.json"), "r") as f:
        flags = json.load(f)
    used_flags = set()

    # Generate port masks for the groups
    group_masks = [random.randrange(0, 1 << 16) for _ in range(args.num_groups)]

    # Generate challenge files for the various stages.
    os.mkdir(args.ctf_dir)
    with open(os.path.join(args.ctf_dir, "group_masks"), "w") as f:
        for mask in group_masks:
            f.write(str(mask) + "\n")
    for i, stage in enumerate(stages):
        stage_num = i + 1
        stagedir = os.path.join(args.ctf_dir, "stage_%02d" % stage_num)
        os.mkdir(stagedir)
        flag_num = get_flag(flags, used_flags, stage)
        assert flag_num is not None, "No flag found matching criteria for stage %d" % (i + 1)
        flagdir = os.path.join(args.flag_pool_dir, "%03d" % flag_num)
        shutil.copyfile(os.path.join(flagdir, "flag"), os.path.join(stagedir, "flag"))
        with open(os.path.join(stagedir, "queries"), "w") as f:
            f.write(str(flags[flag_num][stage.idx]))
        servdir = os.path.join(stagedir, "server")
        os.mkdir(servdir)
        priv = os.path.join(servdir, "priv.key.pem")
        cert = os.path.join(servdir, "cert.crt")
        shutil.copyfile(os.path.join(flagdir, "priv.key.pem"), priv)
        shutil.copyfile(os.path.join(flagdir, "cert.crt"), cert)
        grpdir = os.path.join(stagedir, "group")
        os.mkdir(grpdir)
        shutil.copyfile(os.path.join(flagdir, "pubkey.bin"), os.path.join(grpdir, "pubkey.bin"))
        shutil.copyfile(os.path.join(flagdir, "enc%02d.bin" % stage.idx), os.path.join(grpdir, "enc.bin"))
        material_dir = os.path.join("material/stage%02d" % stage_num)
        if os.path.isdir(material_dir):
            copy_tree(material_dir, grpdir)

    # Generate port numbers for stages
    curr_ports = set()
    for i, stage in enumerate(stages):
        stagedir = os.path.join(args.ctf_dir, "stage_%02d" % (i + 1))
        while True:
            base = random.randrange(3000, 10000)
            ports = [base ^ mask for mask in group_masks]
            if not any(port in curr_ports for port in ports):
                break
        with open(os.path.join(stagedir, "port"), "w") as f:
            f.write(str(base))
        curr_ports.update(set(ports))
        stage.ports = ports

    # Generate server-running stuff
    with open(args.nginx_command, "w") as f:
        ports_str = " -p ".join("%d:%d" % (p, p) for p in curr_ports)
        f.write("docker run --name ctf_servers_nginx1 -p %s -d ctf_servers_nginx" % ports_str)

    with open(args.nginx_conf, "w") as f:
        f.write("events {}\nstream {\n")
        for i, stage in enumerate(stages):
            for group_num in range(args.num_groups):
                ports = []
                for _ in range(stage.servers_per_group):
                    port = random.randrange(3000, 10000)
                    while port in curr_ports:
                        port = random.randrange(3000, 10000)
                    curr_ports.add(port)
                    ports.append(port)
                stage.server_ports.append(ports)
                f.write("\tupstream stage%02d_group%02d {\n\t\tleast_conn;\n" % (i + 1, group_num + 1))
                for serv_port in ports:
                    f.write("\t\tserver %s:%d;\n" % (stage.servers_ip, serv_port))
                f.write("\t}\n")
                f.write("\tserver {\n\t\tlisten %d;\n\t\tproxy_pass stage%02d_group%02d;\n\t}\n" % (stage.ports[group_num], i + 1, group_num + 1))
        f.write("}")

    with open(args.servers_build_command, "w") as f:
        for i, stage in enumerate(stages):
            f.write("# STAGE %02d\n" % (i + 1))
            stagedir = os.path.join(args.ctf_dir, "stage_%02d" % (i + 1))
            key_file = os.path.join(stagedir, "server", "priv.key.pem")
            crt_file = os.path.join(stagedir, "server", "cert.crt")
            f.write("docker build -f servers/Dockerfile_stage -t stage%02d . --build-arg PRIVKEY=%s --build-arg CERT=%s --build-arg STAGE=%d --build-arg NUM_SERVERS=%d\n" % (i + 1, key_file, crt_file, i + 1, stage.threads_per_server))

    with open(args.servers_run_command, "w") as f:
        for i, stage in enumerate(stages):
            for group_num in range(args.num_groups):
                for j, serv_port in enumerate(stage.server_ports[group_num]):
                    f.write("docker run --name stage%02d_group%02d_%02d -p %d:4433 -d stage%02d\n" % (i + 1, group_num + 1, j + 1, serv_port, i + 1))

if __name__ == "__main__":
    sys.exit(main())