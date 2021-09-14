import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity

/**
 * Checks for the existence of of the felix system console.
 * It will try to probe access, but will not report an issue if a login blocks access.
 */
HttpSecurityCheck.create{

    id "nc-d9XVxDQF"

    name "Exposed Felix System Console"

    vulnerability {
        name "Potential RCE: ${name}"
        description '''The Felix login status servlet is exposed and can be used to bruteforce credentials.";"'''
        remediation "Block the path through AEM dispatcher rules. Restrict access completly"
        cve "CWE-749"
        severity Severity.HIGH
    }

    categories 'dispatcher'

    steps([
            {
                name "GET to Felix System Console"

                paths {
                    ['/system/console', '/system/console/bundles', '///system///console', '///system///console///bundles']
                }

                extensions {
                    ["", ".json", ".1.json", ".4.2.1...json", ".css", ".ico", ".png", ".gif", ".html", ".js",
                     ";%0aa.css", ";%0aa.html", ";%0aa.js", ";%0aa.png", ".json;%0aa.ico", ".servlet/a.css",
                     ".servlet/a.js", ".servlet/a.html", ".servlet/a.ico", ".servlet/a.png"]
                }

                header "Authorization", "Basic YWRtaW46YWRtaW4="

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "Web Console"
                    }
                }
            }
    ])

}