import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity

HttpSecurityCheck.create{
    id "test-2"
    details {
        name "Information Disclosure"
        description "CRX should not be accessible"
        remediation "Block CRX access through AEM dispatcher rules."
        cve ""
        severity Severity.HIGH
    }
    steps([
            {
                name "CRX Test 2"

                id "test-2"

                categories "dispatcher","checkerdsl"

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
    ]
    )

}