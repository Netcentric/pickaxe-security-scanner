import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity

HttpSecurityCheck.create{
    id "test-1"
    details {
        name "Information Disclosure"
        description "CRX should not be accessible"
        remediation "Block CRX access through AEM dispatcher rules."
        cve ""
        severity Severity.HIGH
    }
    steps([
            {
                name "CRX Test"
                id "test-1"
                categories "crx","checkerdsl","accesscontrol"
                paths {'/crx/de'}
                paths {
                    ['/crx/de/index.jsp']
                }
                extensions {
                    ['.json']
                }
                method "GET"
                detect {
                    isStatusCode 200
                    bodyContains "CRX","Explorer"
                }
            }
    ])


}