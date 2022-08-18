#!/usr/bin/python3.8
from Crypto.PublicKey import RSA
import Crypto.Cipher.PKCS1_v1_5 as PKCS_1_5
import Crypto.Cipher.PKCS1_OAEP as PKCS_OAEP
from distutils.dir_util import copy_tree
from collections import defaultdict
import random
import json
import os
import sys
import argparse
import shutil
import subprocess
import itertools

class Stage:
    def __init__(self, category, name, servers_per_group, pkcs_class, servers_ip, material_dirname, dockerfile, docker_args):
        self.servers_per_group = servers_per_group
        self.pkcs_class = pkcs_class
        self.port = None
        self.server_ports = []
        self.servers_ip = servers_ip
        self.name = name
        self.material_dir = os.path.join("material", material_dirname)
        self.dockerfile = os.path.join("servers", dockerfile)
        self.docker_args = docker_args

PKCS_CLASSES = {"PKCS_1_5": PKCS_1_5, "PKCS_OAEP": PKCS_OAEP, "None": None}

SUBJ = "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com"

def call(cmd):
    sp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res = sp.wait()
    assert res == 0

def read_stages_conf(conf_filename):
    with open(conf_filename, "r") as f:
        conf = json.load(f)
    stages = defaultdict(list)
    for category in conf:
        assert category.isalnum(), "Invalid category name (only alphanumeric characters allowed): " + category
        for name, spg, pkcs_str, servers_ip, material_dirname, dockerfile, docker_args in conf[category]:
            stages[category].append(Stage(category, name, spg, pkcs_str, servers_ip, material_dirname, dockerfile, docker_args))
    return stages

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-groups", "-n", required=True, type=int)
    parser.add_argument("--nginx-conf", "-c", required=True)
    parser.add_argument("--nginx-command", "-d", required=True)
    parser.add_argument("--servers-build-command", "-s", required=True)
    parser.add_argument("--servers-run-command", "-r", required=True)
    parser.add_argument("--stages-conf", "-g", required=True)
    parser.add_argument("ctf_dir")
    return parser.parse_args()

def main():
    args = parse_args()
    stages = read_stages_conf(args.stages_conf)

    os.mkdir(args.ctf_dir)

    # Generate the servers' key and certificate
    servdir = os.path.join(args.ctf_dir, "server")
    os.mkdir(servdir)
    priv = os.path.join(servdir, "priv.key.pem")
    req = os.path.join(servdir, "request.csr")
    cert = os.path.join(servdir, "cert.crt")
    call(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024",
          "-out", priv])
    call(["openssl", "req", "-new", "-key", priv, "-out", req, "-subj", SUBJ])
    call(["openssl", "x509", "-req", "-days", "365", "-in", req, "-signkey", priv, "-out",
          cert])
    shutil.copyfile(priv, os.path.join("CTFd", "CTFd", "plugins", "cookie_keys", "priv.key.pem"))
    with open(priv, "rb") as f:
        key = RSA.import_key(f.read())
    with open(os.path.join(servdir, "pubkey.bin"), "wb") as f:
        f.write(key.n.to_bytes(key.size_in_bytes(), byteorder="big"))
        f.write(key.e.to_bytes(key.size_in_bytes(), byteorder="big"))

    for category, category_stages in stages.items():
        catdir = os.path.join(args.ctf_dir, category)
        os.mkdir(catdir)
        for i, stage in enumerate(category_stages):
            stage_num = i + 1
            stagedir = os.path.join(catdir, "stage_%02d" % stage_num)
            os.mkdir(stagedir)
            grpdir = os.path.join(stagedir, "group")
            os.mkdir(grpdir)
            shutil.copyfile(os.path.join(servdir, "pubkey.bin"), os.path.join(grpdir, "pubkey.bin"))
            if os.path.isdir(stage.material_dir):
                copy_tree(stage.material_dir, grpdir)

    # Generate port numbers for stages
    internal_ports = set()
    external_ports = set()
    for category, category_stages in stages.items():
        catdir = os.path.join(args.ctf_dir, category)
        for i, stage in enumerate(category_stages):
            stage_num = i + 1
            stagedir = os.path.join(catdir, "stage_%02d" % stage_num)
            while True:
                external = random.randrange(3000, 10000)
                if external not in external_ports:
                    break
            external_ports.add(external)
            with open(os.path.join(stagedir, "port"), "w") as f:
                f.write(str(external))
            stage.port = external
            for _ in range(stage.servers_per_group * args.num_groups):
                while True:
                    internal = random.randrange(3000, 10000)
                    if internal not in internal_ports:
                        break
                internal_ports.add(internal)
                stage.server_ports.append(internal)

    # Generate server-running stuff
    with open(args.nginx_command, "w") as f:
        f.write("set -e\n")
        ports_str = " -p ".join("%d:%d" % (p, p) for p in external_ports)
        f.write("docker run --name ctf_servers_nginx1 -p %s -d ctf_servers_nginx\n" % ports_str)

    with open(args.nginx_conf, "w") as f:
        f.write("events {}\nstream {\n")
        for category, category_stages in stages.items():
            for i, stage in enumerate(category_stages):
                stage_num = i + 1
                upstream_name = "%s_stage%02d" % (category, stage_num)
                f.write("\tupstream %s {\n\t\tleast_conn;\n" % upstream_name)
                for serv_port in stage.server_ports:
                    f.write("\t\tserver %s:%d;\n" % (stage.servers_ip, serv_port))
                f.write("\t}\n")
                f.write("\tserver {\n\t\tlisten %d;\n\t\tproxy_pass %s;\n\t}\n" % (stage.port, upstream_name))
        f.write("}")

    with open(args.servers_build_command, "w") as f:
        f.write("set -e\n")
        for category, category_stages in stages.items():
            f.write("# CATEGORY %s\n" % category)
            for i, stage in enumerate(category_stages):
                stage_num = i + 1
                f.write("## STAGE %02d\n" % stage_num)
                args_str = " --build-arg ".join(stage.docker_args)
                f.write("docker build -f %s -t server_%s_%02d . %s\n" % (stage.dockerfile, category, stage_num, args_str))

    with open(args.servers_run_command, "w") as f:
        f.write("set -e\n")
        for category, category_stages in stages.items():
            for i, stage in enumerate(category_stages):
                stage_num = i + 1
                for j, serv_port in enumerate(stage.server_ports):
                    f.write("docker run --name server_%s_stage%02d_%02d -p %d:4433 -d server_%s_%02d\n" % (category, stage_num, j + 1, serv_port, category, stage_num))

if __name__ == "__main__":
    sys.exit(main())
