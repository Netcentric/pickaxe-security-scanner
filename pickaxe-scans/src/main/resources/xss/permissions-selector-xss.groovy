import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity

/**
 * Checks wether AEM switches the mimetime when requesting the childlist json with an .html extension.
 * It reflects the requested payload in the suffix and makes it executable by rendering it as html instead of json.
 */
HttpSecurityCheck.create{

    id "nc-jyD3urmc"

    name "Reflected XSS vulnerability caused by mimetype switch and privilege parameter reflection"

    vulnerability {
        name "XSS: ${name}"
        description '''Reflected XSS vulnerability caused by mimetype switch when design is called with permissions selector. It reflects the requested payload in the suffix and makes it executable by rendering it as html instead of json. Mimetype switch happens in the dispatcher.'''
        remediation "AEM's Dispatcher must be configured to block the .permissions. selector requests on the respective instance. Especially with .html extensions."
        cve ""
        severity Severity.HIGH
    }

    categories 'xss', 'dispatcher'

    steps([
            {
                name "Inject payload into priviledges response and flip mimetypes"

                paths {
                }

                extensions ".permissions.json/b.html"

                parameters(["privileges": "<svg onload=alert(42)>"])

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        responseHeaderContainsAny "content-type", "text/html"
                        bodyContains "<svg onload="
                    }
                }
            }
    ])
}