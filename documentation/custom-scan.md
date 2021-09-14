# What is a scan or scan execution**?

The term _scan_ refers to a scan configuration which configures the target and the parameters to use when scanning the target. 
This includes settings such as:
* target URLs to scan
* authentication parameters like username or passwords
* configuration location on the filesystem e.g. to define where to pick up check configurations as well 
* location where to write the report

The term _Scan execution_ means a single run of a scan, which results in a report.

# Types of scan configurations
Pickaxe supports multiple types of scan configurations.

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
* Groovy DSL
* YAML 

But be aware the Groovy DSL is way more powerful for this use case as it allows you to overlay 
the build in closures e.g. the ones for authorization or reporting.


# How To: Create a custom scan config using the groovy DSL

If you need a custom scan, meaning that your customizations are not only about checks 
but the whole process then create a groovy or yaml scan definitio.
Please also have a look into the examples module.
Then trigger your scan by passing the --scan <path-to-your-scanfile> parameter to the cli.

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