# Pickaxe Architecture

Pickaxe's main purpose is to easily allow highly configurable and customizable check execution in automated environments.
For instance in build systems or CICD chains.
It is intended around the concept of allowing to change the 
scan process as well as the individual checks, without having to touch the core engine.

Therefore Pickaxe provides a stable and fast framework for scan excution + additional buildin scans and checks. 

## Pickaxe Core
Contains the core scan engine, filesystem loader for checks and the DSL and YAML parsers.
It does only support https/https communication. Pickaxe is pure web app security scanner but not a network security scanner.

## Http Communication
It uses an external HTTP library for communication (okHttp3).
Scan execution is asynchronous and can be throttled.
The number of scan workers is configurable.
It is planned to make the http lib replcable e.g. by apache http and burp's internal. 

Therefore the http library is already wrapped away and will be moved to a separate pluggable module.

### Languages
The module is written in Groovy.

## Pickaxe Scan
Contains the buildin security checksscan engine, a CLI interface and a check loader.
It also build a docker image which contains the CLI and the buildin checks.

### Languages
The module is written in Groovy. Security checks are implemented using the Pickaxe Groovy DSL.

### Dependency Tree

    Pickaxe Scans
    |_____depends on---> Pickaxe Core

## Pickaxe Maven Plugin
Provides a maven plugin which creates a scan configuration and launches it 
using the pickaxe-core project's ScanClient. 
It loads the buildin checks from pickaxe-scan.
There the maven module depends on both projects.

### Dependency Tree

    Pickaxe Maven Plugin
    |_____depends on---> Pickaxe Core
    |_____depends on---> Pickaxe Scans

### Languages
The module is written in Java.