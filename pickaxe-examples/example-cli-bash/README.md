# Run Pickaxe JAR files from CLI 

# Basics
Starts the CLI with URL and output folder parameters and limits the scan to the xss category

    java -jar pickaxe-security-scanner.jar --url http://localhost:45181/content/we-retail/us/en.html --output /Users/thomas/temp --categories xss
    
Starts the CLI with URL and output folder parameters and limits the scan to the xss category

    java -jar pickaxe-security-scanner.jar --url http://localhost:45181/content/we-retail/us/en.html --output /Users/thomas/temp --categories xss

Starts the CLI with URL and output folder parameters and loads scripts located in the scripts folder    
    
    java -jar pickaxe-security-scanner.jar --url http://localhost:45181/content/we-retail/us/en.html --output /home/output --load /home/scripts
    
Starts the CLI and generate an ID    
    
    java -jar pickaxe-security-scanner.jar --id 

## Load a custom scan configuration

In this example we are loading a custom scan configuration located in this module's src/main/resources folder.
Open the folder and you will notice multiple config files

    java -jar pickaxe-security-scanner.jar \
        --url http://localhost:45181/content/we-retail/us/en.html \
        --output /home/output \
        --scan src/main/resources/scan.yaml

## Load a custom check configuration