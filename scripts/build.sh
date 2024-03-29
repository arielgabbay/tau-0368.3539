#!/bin/bash
set -e
if [ -d ctf/ ]; then
	echo "ctf/ directory exists." 1>&2
	exit 1
fi
if [ ! $# = 1 ]; then
	echo "Usage: $0 <num_of_groups>" 1>&2
	exit 2
fi
# Run prepare.py
mkdir -p nginx/conf
python scripts/prepare.py ctf -n $1 --nginx-conf nginx/conf/nginx.conf --nginx-command scripts/run_nginx.sh --servers-build-command scripts/build_servers.sh --servers-run-command scripts/run_servers.sh --stages-conf stages.json
# Create zip files for groups
for grpdir in ctf/*/*/group; do
	cd "$grpdir"
	zip -r ../files.zip .
	cd -
done
# Update CTFd export files
rm -r CTFd_export/db || true
mkdir CTFd_export/db
cp -r CTFd_export/db_base/* CTFd_export/db
rm CTFd_export/db/pool_flags.json || true
python scripts/update_ctfd.py
# Create CTF import file
rm CTFd_export/ctf_import.zip || true
cd CTFd_export
zip -r ctf_import.zip db/ uploads/
cd ..
# Build nginx image
cd nginx
docker build -t ctf_servers_nginx .
cd ..
# Build base server image
docker build -f servers/Dockerfile_base -t ctf_server_base . --build-arg MBEDTLS=mbedtls
# Build server images
chmod +x scripts/build_servers.sh
./scripts/build_servers.sh
# Build CTFd image
cd CTFd/
docker-compose build
