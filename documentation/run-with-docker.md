# Use Pickaxe with Docker
With each build of the pickaxe-scans module 
a Docker container tagged netcentric/pickaxe-security-scanner:latest is created.

Check your local images to find it by using the ps command.

    docker images

## Run Pickaxe in Docker
The pickaxe docker container requires you to mount the output directory when started.
Any additional arguments are forwarded into the container's run statement it forwarded to the CLI.
The following example shows how to simply run the docker container to scan a local AEM instance on the docker envs host system
with all build-in checks.

    docker run --rm -it -v /Users/<your-home>/temp/output:/app/output netcentric/pickaxe-security-scanner:latest --url http://host.docker.internal/content/we-retail/us/en.html

You can add any of the additional CLI commands to the build,
but be aware that internally, the entrypoint.sh will automatically append the following arguments to mount the output and checks volumes (They can not be overriden).

    --output /app/output --location /app/checks

## Volumes
The following volumes are available:

Volume for output. This is where the containerized runs are writing their reports.
It is added by default to any run of the docker container.

    /app/output

Volume for custom checks. This is where you can place your custom checks. Nested folder structures are possible.
It is added by default to any run of the docker container.

    /app/checks

Volume for custom scans.
This is where you should place your custom scan config. It is NOT added to a scan be default.

    /app/scan

## Debug Pickaxe when running with Docker

If you need to check any of the resources deployed with pickaxe or need 
to interact with the internal structure, 
then try to get a shell in the pickaxe docker container.

    docker run --rm -it -p 8090:8090 \
        -v /Users/<your-home>/temp/output:/app/output \
        --entrypoint /bin/sh netcentric/pickaxe-security-scanner:latest

