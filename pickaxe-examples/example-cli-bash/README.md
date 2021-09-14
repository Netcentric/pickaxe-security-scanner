#!/bin/bash

Starts the CLI with URL and output folder parameters and limits the scan to the xss category

    java -jar aem-security-scans-1.0-SNAPSHOT-jar-with-dependencies.jar --url http://localhost:45181/content/we-retail/us/en.html --output /Users/thomas/temp --categories xss
    
Starts the CLI with URL and output folder parameters and limits the scan to the xss category

    java -jar aem-security-scans-1.0-SNAPSHOT-jar-with-dependencies.jar --url http://localhost:45181/content/we-retail/us/en.html --output /Users/thomas/temp --categories xss

Starts the CLI with URL and output folder parameters and loads scripts located in the scripts folder    
    
    java -jar aem-security-scans-1.0-SNAPSHOT-jar-with-dependencies.jar --url http://localhost:45181/content/we-retail/us/en.html --output /home/output --load /home/scripts
    
Starts the CLI and generate an ID    
    
    java -jar aem-security-scans-1.0-SNAPSHOT-jar-with-dependencies.jar --id 