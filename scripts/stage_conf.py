import json
import os
from collections import defaultdict

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
        self.category = category

def read_stages_conf(conf_filename):
    with open(conf_filename, "r") as f:
        conf = json.load(f)
    stages = defaultdict(list)
    for category in conf:
        assert category.isalnum(), "Invalid category name (only alphanumeric characters allowed): " + category
        for name, spg, pkcs_str, servers_ip, material_dirname, dockerfile, docker_args in conf[category]:
            stages[category].append(Stage(category, name, spg, pkcs_str, servers_ip, material_dirname, dockerfile, docker_args))
    return stages

