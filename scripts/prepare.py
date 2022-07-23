from Crypto.PublicKey import RSA
import Crypto.Cipher.PKCS1_v1_5 as PKCS_1_5
import Crypto.Cipher.PKCS1_OAEP as PKCS_OAEP
import random
import os
import sys
import argparse
import subprocess

FLAGSIZE = 16

class Stage:
    def __init__(self, servers_per_group, threads_per_server, pkcs_class):
        self.servers_per_group = servers_per_group
        self.threads_per_server = threads_per_server
        self.pkcs_class = pkcs_class
        self.ports = None
        self.server_ports = []

STAGES = [
    Stage(2, 5,  PKCS_1_5),  # Bleichenbacher simple oracle
    Stage(1, 15, PKCS_1_5),  # Bleichenbacher simple oracle, parallel queries
    Stage(2, 5,  PKCS_1_5),  # Bleichenbacher timing oracle (1)
    Stage(1, 15, PKCS_1_5),  # Bleichenbacher timing oracle (1), parallel queries
    Stage(2, 5,  PKCS_1_5),  # Bleichenbacher timing oracle (2)
    Stage(1, 15, PKCS_1_5),  # Bleichenbacher timing oracle (2), parallel queries
    Stage(2, 5,  PKCS_OAEP), # Manger simple oracle
    Stage(1, 15, PKCS_OAEP)  # Manger simple oracle, parallel queries
]

SUBJ = "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com"

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-groups", "-n", required=True, type=int)
    parser.add_argument("--nginx-conf", "-c", required=True)
    parser.add_argument("--nginx-command", "-d", required=True)
    parser.add_argument("--servers-build-command", "-s", required=True)
    parser.add_argument("--servers-run-command", "-r", required=True)
    parser.add_argument("--servers-ip", "-i", required=True)
    parser.add_argument("ctf_dir")
    return parser.parse_args()

def generate_group(priv, pub, enc, flag, pkcs_class):
    key = RSA.import_key(open(priv, "rb").read())
    pkcs = pkcs_class.new(key)

    with open(pub, "wb") as f:
        f.write(key.n.to_bytes(key.size_in_bytes(), byteorder="big"))
        f.write(key.e.to_bytes(key.size_in_bytes(), byteorder="big"))

    with open(enc, "wb") as f:
        f.write(pkcs.encrypt(flag))

def call(cmd):
    sp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res = sp.wait()
    assert res == 0, "Command\n%s\nreturned %d; stderr is:\n%s" % (" ".join(cmd), res, sp.stderr.read())

def main():
    args = parse_args()

    # Generate port masks for the groups
    group_masks = [random.randrange(0, 1 << 16) for _ in range(args.num_groups)]

    # Generate challenge files for the various stages.
    os.mkdir(args.ctf_dir)
    with open(os.path.join(args.ctf_dir, "group_masks"), "w") as f:
        for mask in group_masks:
            f.write(str(mask) + "\n")
    for i, stage in enumerate(STAGES):
        stage_num = i + 1
        stagedir = os.path.join(args.ctf_dir, "stage_%02d" % stage_num)
        os.mkdir(stagedir)
        flag = os.urandom(FLAGSIZE)
        with open(os.path.join(stagedir, "flag"), "w") as f:
            f.write(flag.hex())
        servdir = os.path.join(stagedir, "server")
        os.mkdir(servdir)
        priv = os.path.join(servdir, "priv.key.pem")
        req = os.path.join(servdir, "request.csr")
        cert = os.path.join(servdir, "cert.crt")
        call(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024",
              "-out", priv])
        call(["openssl", "req", "-new", "-key", priv, "-out", req, "-subj", SUBJ])
        call(["openssl", "x509", "-req", "-days", "365", "-in", req, "-signkey", priv, "-out",
              cert])
        grpdir = os.path.join(stagedir, "group")
        os.mkdir(grpdir)
        generate_group(priv, os.path.join(grpdir, "pubkey.bin"), os.path.join(grpdir, "enc.bin"),
                       flag, stage.pkcs_class)

    # Generate port numbers for stages
    curr_ports = set()
    for i, stage in enumerate(STAGES):
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
        for i, stage in enumerate(STAGES):
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
                    f.write("\t\tserver %s:%d;\n" % (args.servers_ip, serv_port))
                f.write("\t}\n")
                f.write("\tserver {\n\t\tlisten %d;\n\t\tproxy_pass stage%02d_group%02d;\n\t}\n" % (stage.ports[group_num], i + 1, group_num + 1))
        f.write("}")

    with open(args.servers_build_command, "w") as f:
        for i, stage in enumerate(STAGES):
            f.write("# STAGE %02d\n" % (i + 1))
            stagedir = os.path.join(args.ctf_dir, "stage_%02d" % (i + 1))
            key_file = os.path.join(stagedir, "server", "priv.key.pem")
            crt_file = os.path.join(stagedir, "server", "cert.crt")
            f.write("docker build -f servers/Dockerfile_stage -t stage%02d . --build-arg PRIVKEY=%s --build-arg CERT=%s --build-arg STAGE=%d --build-arg NUM_SERVERS=%d\n" % (i + 1, key_file, crt_file, i + 1, stage.threads_per_server))

    with open(args.servers_run_command, "w") as f:
        for i, stage in enumerate(STAGES):
            for group_num in range(args.num_groups):
                for j, serv_port in enumerate(stage.server_ports[group_num]):
                    f.write("docker run --name stage%02d_group%02d_%02d -p %d:4433 -d stage%02d\n" % (i + 1, group_num + 1, j + 1, serv_port, i + 1))

if __name__ == "__main__":
    sys.exit(main())