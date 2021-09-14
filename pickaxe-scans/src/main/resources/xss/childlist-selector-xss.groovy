import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity

/**
 * Checks wether AEM switches the mimetime when requesting the childlist json with an .html extension.
 * It reflects the requested payload in the suffix and makes it executable by rendering it as html instead of json.
 */
HttpSecurityCheck.create{

    id "nc-oK6X4NAp"

    name "Reflected XSS vulnerability caused by mimetype switch"

    vulnerability {
        name "XSS: ${name}"
        description '''Reflected XSS vulnerability caused by mimetype switch when design is called with childlist selector. It reflects the requested payload in the suffix and makes it executable by rendering it as html instead of json. Mimetype switch happens in the dispatcher.'''
        remediation "AEM's Dispatcher must be configured to block the .childlist. selector requests on the respective instance. Especially with .html extensions."
        cve ""
        severity Severity.HIGH
    }

    categories 'xss', 'dispatcher'

    steps([
            {
                name "Inject payload to childrenlist servlet and check for response type flipping"

                paths {
                    ["/etc/designs/<h1>.childrenlist.json//<svg onload=alert(1)>.html"]
                }

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        responseHeaderContainsAny "content-type", "text/html"
                        bodyContains "<svg onload=alert(1)>.html"
                    }
                }
            }
    ])
}