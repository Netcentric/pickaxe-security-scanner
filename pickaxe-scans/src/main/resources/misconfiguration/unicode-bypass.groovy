import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.payload.FilterEvasion

HttpSecurityCheck.create{

    id "nc-UniC7eLvR"

    name "AEM Unicode Dispatcher Bypass"

    vulnerability {
        name "Information Disclosure and Enumeration: ${name}"
        description '''Assess to pages with numeric selectors and e.g. json renderers should be blocked. 
            Latin characters could be substituted for an equivalent number in another language, bypassing the dispatcher rule that only looks for Latin characters and allows content grabbing.
        '''
        remediation "Allow only known sling selectors in latin languages."
        cve ""
        severity Severity.HIGH
    }

    categories 'aem-misconfig','dispatcher'

    steps([
            {
                name "GET to target URL with all dispatcher bypasses"

                extensions FilterEvasion.UNICODE_CHARACTER_BYPASSES.getRandomizedBypasses(9)

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