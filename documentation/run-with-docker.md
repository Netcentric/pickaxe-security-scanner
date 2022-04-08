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

    docker run --rm -it -v /Users/thomas/<your-home>/pickaxe-scans:/app/output ghcr.io/netcentric/pickaxe-security-scanner:latest --url http://host.docker.internal/content/we-retail/us/en.html

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
        --entrypoint /bin/sh  ghcr.io/netcentric/pickaxe-security-scanner:latest

# Potential Errors

## Missing docker runtime

If your build fails with the following error then please make sure that a docker daemon is running. 
Therefore a docker client needs to be available.
 
    Cannot create docker access object : Connection refused


## Image or image version not found

If you get an error message indicating the image was not found e.g. 
    
    Unable to find image 'netcentric/pickaxe-security-scanner:latest' locally

then please check your available images and check wether the utilized image name or version are correct.

    docker images 

## Local working directory not accessible

Another common error is a non-existing or non-accessible output directory with non docker desktop container runtimes. 
This directory is mounted by your docker container and used to share the scan results with you.
If your docker runtime can not find or access it the following message might appear.

    docker: Error response from daemon: error while creating mount source path '/Users/<user>/output': chown /Users/<user>/output: permission denied.

The issue might be caused by your container runtime as especially colima does use a non-root user to execute
container task and might not see the underlying filesystem.

To fix it there are multiple options:
- Update your container runtime see https://github.com/abiosoft/colima/issues/2
- Create the directory and give write access to other users using chmod 775 (be careful potentially unsafe)
