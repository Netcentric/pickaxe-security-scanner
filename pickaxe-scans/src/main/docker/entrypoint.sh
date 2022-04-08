#!/bin/bash
echo "$@"
echo "Running Scanner"

# Add the following to java -jar if you need to debug
# -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=*:8090
# it is going to stop the process and waits on port 8090 for a debugger

java -jar /app/pickaxe-security-scanner.jar $@ --output /app/output --location /app/checks