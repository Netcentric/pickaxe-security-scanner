import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.payload.Credential
import biz.netcentric.security.checkerdsl.payload.FilterEvasion


HttpSecurityCheck.create{

    id "nc-curUpkC0s"

    name "CurrentUserServlet is exposed"

    vulnerability {
        name "Credential Leakage: ${name}"
        description '''It is possible to harvest valid usernames from jcr:createdBy, jcr:lastModifiedBy, cq:LastModifiedBy attributes of any JCR node which can be used to bruteforce into the system.'''
        remediation "Block access to the affected servlet on publish through AEM dispatcher rules or disable it completely."
        cve "CWE-200"
        severity Severity.HIGH
    }

    categories 'aem-misconfig','dispatcher'

    steps([
            {
                name "GET request to user status servlet was successfully responded."

                paths {
                    ["/libs/granite/security/currentuser", "///libs///granite///security///currentuser"]
                }

                extensions FilterEvasion.JSON_EVASION.getBypasses()

                Credential.getAll().each { cred ->
                    basicAuthentication cred
                }


                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "type"
                    }
                }
            }
    ])

}