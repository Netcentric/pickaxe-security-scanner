![pickaxe-logo2-kl](https://user-images.githubusercontent.com/3109217/134664102-fad8ef35-68da-4466-aa22-8558638c2109.png)
# Pickaxe - AEM and Dispatcher Security Scanner

Securing an AEM installation requires to continuously check the overall stack. Any failure in one of the involved layers may likely affect a totally different technical layer or even the whole platform.

The purpose if this project is to simplify continuous automated security testing of Adobe Experience Manager and especially the AEM Dispatcher.
If further enables projects to customize the actual test behaviou to specific project requirements and to easily add additional project specific checks.

## Highly customizable for your project needs

Pickaxe is scriptable web application test framework with a customizable http scan engine and a large predefined set of security checks for Adobe Experience Manager (AEM) projects.

It can be easily customized and extended either through a groovy based DSL or using YAML based scan and check configurations.

The scanner can be integrated 
* into a maven project, 
* started from docker container 
* or simply called via it's commandline interface.


Pickaxe is fully customizable without having to touch or change the project's core and 
is designed to be integrated into build and CICD ecosystems. 

But Pickaxe is not necessarily limited to AEM only and could be used to scan other web applications and API services.

## Features 

What is in for my project if I decide to use Pickaxe?

- More than 35 build-in Dispatcher and AEM Security Checks
- Easy integration or run locally 
    - Commandline Interface
    - Maven build integration as a maven plugin
    - Easy Jenkins integration
- Fully configurable and customizable scans and checks for any project need
    - Groovy Configuration DSL
    - YAML Configuration
- Authentication support
- Fast and scalable through async and parallel scan execution
- Multiple report handlers and formats (html, json, console or just-break-the-build)

# Attack Vectors

Please check [Pickaxe Scans Module Readme](/pickaxe-scans/README.md) for a list of all supported attack vectors.

# Installation

* [Maven Build Integration](/documentation/run-with-maven.md)
* [Run from Commandline](/documentation/run-with-cli.md)
* [Run via Docker](/documentation/run-with-docker.md)

# Scan Configuration

Before starting to deep dive into advanced topics, 
it is crucial to understand the domain specific terminology and meaning of certain buzzwords.

| Term    | Description |
|---------|-------------|
| scan| The term _scan_ refers to a scan configuration which configures the target and the parameters to use when scanning the target. |
| check   | The term check refers to a single configuration which tells the scanner how to attack a certain vulnerability. | 
| reporter  |   A reporter is a report handlers or writer which is used to process the scan results and acts according to it's implementation. It can either print output or terminate further processing when issues are detected.|  
| config dsl  |  Configuration language to influence the runtime behaviour of the scan angine usig an external configuration. |    

### Advanced Configurations

* [Custom Scan Configurations](/documentation/custom-scan.md)
* [Custom Security Checks](/documentation/custom-checks.md)
* [Reporting Configurations](/documentation/reporting.md)

## Configuration Languages: Groovy vs. YAML

Pickaxe uses either a Groovy Configuration DSL or a YAML config to allow customization or configuration of the scan process or to define custom checks.
The Groovy DSL refers to the scan engines domain specific configuration language, which is used to define most buildin scans or checks.
The YAML config is a way simpler format which allows quick customizations without needing to now any internals.

* The scan engine interprets and understands it and acts accordingly.
* It can be loaded via filesystem and dynamically extend the capabilities of the scanner.
* If you want to keep it simpler, then just go for the YAML based configs, but be aware the groovy DSL is more powerful.

# Questions

If you have any questions which are still answered after reading the documentation feel free to raise them in the discussion forum.


# Contributions

Contributions are highly welcome in the form of issue reports, pull request or providing help in our discussion forum.

## Pickaxe Development and Backlog

If you want to contribute or develop on top of pickaxe please have a look into the following documentation chapters.

* [Runtime Requirements](/documentation/requirements.md)
* [Pickaxe Architecture](/documentation/architecture.md)
* [Pickaxe Development](/documentation/development.md)
* [Product Features and Backlog](/documentation/backlog.md)

# License
Pickaxe is licensed under the Eclipse Public License - v 1.0.
