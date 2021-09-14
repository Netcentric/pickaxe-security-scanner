import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.payload.FilterEvasion

HttpSecurityCheck.create {

    id "nc-SSRFpkC0s"

    name "Potential Server-Side Request Forgery through Sales Force Servlet"

    vulnerability {
        name "Server-Side Request Forgery: ${name}"
        description """An attacker could exploit this issue to target internal systems behind the firewall, or services running on the local server’s loopback network interface, which are typically inaccessible from the outside world.
By using a Server-Side Request Forgery attacks it is possible to 
scan and attack systems on the internal network inside the perimeter firewall, enumerate and attack services that are running on these hosts and to bypass host-based authentication services if the vulnerable server is whitelisted.
This check does only verify if the known endpoint could be accessed."""
        remediation "Block access to the affected servlet on publish through AEM dispatcher rules or disable it completely."
        cve "CWE-918"
        severity Severity.HIGH
    }

    categories "aem-misconfig", "dispatcher", "ssrf"

    steps([
            {
                name "GET request to sales force servlet is successfully responded."

                paths {
                    ["/libs/mcm/salesforce/customer", "///libs///mcm///salesforce///customer"]
                }

                extensions FilterEvasion.SERVLET_ENUMERATION_WITH_BYPASS_PLACEHOLDER.getRandomizedBypasses(9)

                querystring "customer_key=x&customer_secret=y&refresh_token=z&insta nce_url=http://someunknownendpoint.com/"

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "success"
                    }
                }
            }
    ])
}