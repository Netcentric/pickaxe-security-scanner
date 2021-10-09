# Development

The project is build using maven and mainly based on Groovy and Java.
It consists of the following components.

| Module | Purpose | Stack |
|---------|-------------|-------------|
| pickaxe-core  | Core scan engine and checks loader. | Groovy | 
| pickaxe-scans  | Security checks lib on top of core and commandline interface. Depends on pickaxe core | Groovy |
| pickaxe-maven-plugin  | Maven plugin for build integration. Depends on the pickaxe-core and pickaxe-scans modules | Java |
| pickaxe-examples  | A number of example cases to demonstrate build and CI integration, custom checks and custom scans |  |

## How to build

Clone the project and run maven

    mvn clean install

## How to contribute

Clone the project and create a feature branch.
Add you contribution and create a pull request.

Please make sure to unit test your changes.
For new security checks please add a mock test.

## How to release

Pull latest develop and master.
Checkout the develop branch
Run the following script from the root of the project.

    ./release.sh
    
## Requirements

Extending Pickaxe requires the following software packages to be available.
* OpenJDK 11
* Apache Maven 3.6.x
* Docker Engine - Community
