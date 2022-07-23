#!/bin/bash
set -e
if [ -d ctf/ ]; then
	echo "ctf/ directory exists." 1>&2
	exit 1
fi
if [ ! $# = 2 ]; then
	echo "Usage: $0 <num_of_groups> <servers_ip>" 1>&2
	echo "Notice that to run nginx on the same machine as the servers, server IP needs to be 172.17.0.1" 1>&2
	exit 2
fi
# Create CTF import file
rm -f CTFd/ctf_import.zip
cd CTFd
zip -r ctf_import.zip db/
cd ..
# Run prepare.py
mkdir -p nginx/conf
python3.8 scripts/prepare.py ctf -n $1 --nginx-conf nginx/conf/nginx.conf --nginx-command scripts/run_nginx.sh --servers-build-command scripts/build_servers.sh --servers-run-command scripts/run_servers.sh --servers-ip $2
# Build nginx image
cd nginx
docker build -t ctf_servers_nginx .
cd ..
# Build base server image
docker build -f servers/Dockerfile_base -t ctf_server_base . --build-arg MBEDTLS=mbedtls
# Build server images
chmod +x scripts/build_servers.sh
./scripts/build_servers.sh
