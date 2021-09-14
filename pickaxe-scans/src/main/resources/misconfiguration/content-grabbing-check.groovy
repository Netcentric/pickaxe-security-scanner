import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.payload.FilterEvasion

HttpSecurityCheck.create{

    id "nc-OYJ7eLvR"

    name "AEM default renderers exposed"

    vulnerability {
        name "Information Disclosure and Enumeration: ${name}"
        description '''The page is leaking information which is not supposed to be shared with the outside world. 
                AEM's dispatcher must block access to any URL that leaks metadata.
                Please check the URL's manually.'''
        remediation "Allow only known sling selectors and URL extensions based on on whitelist."
        cve "CWE-668"
        severity Severity.HIGH
    }

    categories 'aem-misconfig','dispatcher'

    steps([
            {
                name "GET to target URL with all dispatcher bypasses"

                extensions FilterEvasion.SERVLET_ENUMERATION_WITH_BYPASS_PLACEHOLDER.getRandomizedBypasses(9)

                method "GET"

                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "jcr:createdBy", "jcr:lastModifiedBy", "rep:principalName", "rep:password", "rep:authorizableId"
                    }
                }
            }
    ])

}
