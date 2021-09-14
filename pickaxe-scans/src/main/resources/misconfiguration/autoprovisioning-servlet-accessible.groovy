import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.payload.Encoding
import biz.netcentric.security.checkerdsl.payload.FilterEvasion

/**
 * Based on https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=87
 * We do not try to exploit it but check wether the endpoint is accessible for the outside world. This should be enough.
 */
HttpSecurityCheck.create {

    id "nc-autoPXcd3"

    name "Server-Side Request Forgery through Autoprovisioning Servlet may lead to RCE"

    vulnerability {
        name "Potential RCE: ${name}"
        description """An SSRF in the autoprovisioning servlet can be used to smuggle in requests to the TopologyConnectorServlet and to silently add a fake malicious AEM node with active reverse replication which is initiated automatically. This would open the environment to RCE."""
        remediation "Block access to the affected servlet on publish through AEM dispatcher rules or disable it completely."
        cve ""
        severity Severity.HIGH
    }

    categories "aem-misconfig", "rce", "ssrf"

    steps([
            {
                name "POST request to provisioning servlet results in a 200 or 500 response."

                paths {
                    ["/libs/cq/cloudservicesprovisioning/content/autoprovisioning",
                     "///libs///cq///cloudservicesprovisioning///content///autoprovisioning"]
                }

                extensions FilterEvasion.SERVLET_ENUMERATION_WITH_BYPASS_PLACEHOLDER.getRandomizedBypasses(9)

                def callbackServer = Encoding.toBase64("http://someunknownendpoint.com/")
                def data = """servicename=analytics&analytics.server=${callbackServer}&analytics.company=1&analytics.username=2&analytics.secret=3&analytics.reportsuite=4"""

                body "text/html", "UTF-8", { data }


                method "POST"
                detect {
                    all {
                        checkStatusCode 200
                    }

                    all {
                        checkStatusCode 500
                        bodyContains "Provisioning"
                    }
                }
            }
    ])
}