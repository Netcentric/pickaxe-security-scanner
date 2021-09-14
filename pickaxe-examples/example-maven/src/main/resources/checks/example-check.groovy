package checks

import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity



HttpSecurityCheck.create{

    id "nc-example-123"

    name "AEM Example Check to demonstrate the loading behaviour"

    vulnerability {
        name "Information Disclosure: ${name}"
        description '''AuditServletDetector exposed and might expose audit log information. \n
                    See https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=96'''
        remediation "Block to the audit servlet on publish through AEM dispatcher rules."
        cve "CWE-668"
        severity Severity.HIGH
    }

    categories 'aem-misconfig','dispatcher'

    steps([
            {
                name "GET request to audit servlet paths"

                paths {
                    ['/bin/msm/example', '///bin///msm///example']
                }

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "results"
                    }
                }
            }
    ])

}