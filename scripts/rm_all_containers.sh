#!/bin/bash
docker container stop $(docker ps -aq)
docker container rm $(docker ps -aq)
