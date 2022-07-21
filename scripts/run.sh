#!/bin/bash
set -e
chmod +x scripts/run_nginx.sh
./scripts/run_nginx.sh
chmod +x scripts/run_servers.sh
./scripts/run_servers.sh
