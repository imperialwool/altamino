#!/bin/bash
sysctl vm.overcommit_memory=1
redis-server --daemonize yes
uvicorn main:app --host "0.0.0.0" --port 80