# What is a scan or scan execution**?

The term _scan_ refers to a scan configuration which configures the target and the parameters to use when scanning the target. 
This includes settings such as:
* target URLs to scan
* authentication parameters like username or passwords
* configuration location on the filesystem e.g. to define where to pick up check configurations as well 
* location where to write the report

The term _Scan execution_ means a single run of a scan, which results in a report.

# Types of scan configurations
Pickaxe supports multiple types of scan configurations which can be defined 
* via YAML config
* via the Groovy DSL (internal or framework users only)
* as a maven plugin configuration 
* by passing in the required parameters to the CLI interface

## CLI default or build-in scan config
If you run Pickaxe via the CLI or Docker build and do not explicitly reference a custom external scan configuration,
the pickaxe will use the default config which can be configured using the CLI's parameters.
So you do not have to do anything beyond calling pickaxe via CLI and passing  a URL and output folder to it.

## Maven scan config
If you run Pickaxe via maven plugin, then the default scan configuration (same as CLI) will be used.
But it will be customized using the maven plugin's configuration parameters. 

## External scan configurations
If you are not happy with the existing default scan configuration or 
have custom requirements e.g. in terms of authentication then a custom scan config might be a good fit.
It can be defined using one of both configuration languages
* YAML 
* Groovy DSL (internal or framework users only)

But be aware the Groovy DSL is way more powerful for this use case as it allows you to overlay 
the build in closures e.g. the ones for authorization or reporting. 
Therefore it is right now not exposed via the CLI client and can only be used as a consumer of the core framework e.g. if your implement your own CLI.


# Create a custom YAML scan config 

If you need a custom scan, meaning that your customizations are not only about checks 
but the whole process then create a groovy or yaml scan definition.
Please also have a look into the examples module.

Create a scan config file

    touch <path-to-your-scanfile>.yaml

Then trigger your scan by passing the --scan <path-to-your-scanfile>.yaml parameter to the cli.
    
    # Mandatory: System under test. Make sure to have a content page in the actual URL as we mutate it for some checks quite a bit.
    target: https://my.target-website.com/content/us/en.html
    # (Optional) load checks from the defined local filesystem location
    register:
      - "/home/cicd-user/securityscans/custom-checks"
    scanConfig:
      # (Optional): Pre authenticate before running the checks
      authentication:
        authenticationType: "simple"
        username: "basic-authentication-user"
        password: "basic-authentication-pw"
        token: "none"
      # (Optional): Set to false if you want to ignore the buildin checks
      buildIn: true
      runAllChecks: false
      # (Optional) Be aware if you define a category then not all buildin checks will be used
      categories:
        - "xss"
        - "crx"
      # (Optional) Be aware if you declare checkIds then only these checks will be used
      checkIds:
        - "xxsasd"
        - "xysasd"
    reporter:
      # Select the desired reporting behaviour
      handlers:
        - "json-pretty"
        - "html-table"
        - "console-log-build-breaker"
      # Mandatory: This is where we write the reports
      outputFolder: "/home/cicd-user/securityscans/reports"
    
## Configuration Options
    
    
# Advanced: Create a custom scan from your own Scan Client 


## Detailed Steps

Create a scan config file

    touch my-scan-config.groovy

Add the content's of the scan config to your groovy file.

    {
                target "The target URL"
    
                config {
                    if(selectedCategories.size() > 0){
                        categories(selectedCategories)
                    }else{
                        runAllChecks true
                    }
                }
    
                reporter {
                    register "json-pretty"
                    
                    // comfig is optional
                    config {
                        log.info "Reporting to " + outputLocation
                        setOutputLocation "your output location"
                    }
                }
    
                BuildinAEMChecks checks = new BuildinAEMChecks(securityCheckProvider: securityCheckProviderDelegate)
                checks.init()
     }

Now reference the scan config when starting your Pickaxe run.

     java -jar <pickaxe.jar> --url <target> --output <outputfolder> --scan <path-to-your-scanfile> 
