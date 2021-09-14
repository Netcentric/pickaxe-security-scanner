# Pickaxe Examples

## CLI Example

The CLI example contains a custom scan.yaml and a custom check to show how a customized setup may look like.
Please check the [example specific README for details.](../example-cli-bash/README.md)

## Maven Build Integration Example

The maven integration example contains a pom.xml with a full setup which runs 
as a part of a maven build.

## Jenkinsfile Example

The Jenkinsfile setup contains a jenkinsfile which triggers the scan. 
It relies on a pom.xml which is also part of the setup and configures the scan execution.

Reports are published after finishing the scan.