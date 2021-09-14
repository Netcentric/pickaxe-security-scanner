import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.payload.FilterEvasion

/**
 * Checks wether AEM saved search selector triggered error page reflects the path parameter into a link which is reflected XSS triggering on click in the context of the target website.
 */
HttpSecurityCheck.create {

    id "nc-I56crx6W"

    name "Reflected XSS DAM metadata merge"

    vulnerability {
        name "XSS: ${name}"
        description """Meta data merge dialog can be used to trigger a reflected XSS. 
Provoking an error when calling the preferences dialog directly causes an XSS if the response does not return the application/json content type as a response header. 
The response might then be interpreted as an html and the output encoding is rendered useless."""
        remediation "Update AEM to the most recent version and make sure the content-type header is set correctly."
        cve ""
        severity Severity.HIGH
    }

    categories 'xss', 'crx'

    steps([
            {
                name "Inject payload into savedsearch selector error page and flip mimetype"

                paths {
                    ["/libs/dam/merge/metadata","///libs///dam///merge///metadata"]
                }

                extensions FilterEvasion.HTML_DISPATCHER_BYPASS_EXTENSIONS.getRandomizedBypasses(9)

                parameters(["path": "/etc<"])

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "assetPaths", "/etc<"
                        responseHeaderIsMissing "Content-Type", "application/json"
                    }
                }
            }
    ])
}