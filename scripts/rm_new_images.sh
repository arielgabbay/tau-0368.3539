#!/bin/bash
docker image rm $(docker image ls | grep minutes | awk '{print $1}')
