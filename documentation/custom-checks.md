# What is a Check or Security Check?

The term check refers to a single configuration which tells the scanner how to attack a certain vulnerability.

Each check contains a vulnerability description and one or multiple steps which provide settings for the scan enghine and evaluation criteria to identify if the
step has been successful.

Each check contains at least one step, but may contain more depending on the complexity of the check.
Steps are executed in sequential order and require the predecessor to be successful.

# Working with Security Checks

## How To: Configure the usage of build-in checks
Build in checks are build into the framework and are always present. Please set the config option

    config {
        runAllChecks true
    }

or alternatively select specific categories.

    config {
        categories xss, dispatcher, misconfiguration
    }


If no categories are selected then all checks are enabled by default.

## How To: Define your own groovy checks

The following snippet which tests the availability of CRX can be placed in a groovy file and
then loaded by the security checkers lib's CLI interface.

    import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
    import biz.netcentric.security.checkerdsl.model.Severity
    
    HttpSecurityCheck.create{
        name "CRX Test"
        categories "crx","checkerdsl","accesscontrol"
        vulnerability {
            name "Information Disclosure"
            description "CRX should not be accessible"
            remediation "Block CRX access through AEM dispatcher rules."
            cve ""
            severity Severity.HIGH
        }
    
        // supports GET and POST
        method "GET"
    
        // can be a closure returning a list
        paths {
            ['/crx/de/index', '/crx/de']
        }
        
        // can be a closure returning a list
        extensions {
            ['', '.jsp']
        }
        
        // supposed to be a list 
        headers(["Authorization", "sdsadadsadadsadda"])
        
        // supposed to be a list 
        parameters(["query", "xyz"])
        
        detect {
            all{
                isStatusCode 200
                bodyContains "CRX","Explorer"
            }
        }
    
    }  

Please check the examples and add the folder where the custom checks are located to your location property.
The scan engine's checkloader will process the complete folder tree and look for .groovy and .yaml files