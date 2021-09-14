import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity

HttpSecurityCheck.create{

    id "nc-OwJ7gLvR"

    name "Forms servlet url allows to read access protected resources in the repository tree"

    vulnerability {
        name "Information Disclosure and Enumeration: ${name}"
        description '''The .form.pdf selector combination can be used to access and also traverse any path following it as an HTTP suffix.'''
        remediation "Allow only known sling selectors and URL extensions based on on whitelist."
        cve "CWE-668"
        severity Severity.HIGH
    }

    categories 'dispatcher'

    steps([
            {
                name "GET to forms.pdf servlet to bypass dispatcher"

                paths {
                    [".form.pdf/content/usergenerated.children.-1..json", "/content.form.pdf/content.children.1..json"]
                }

                method "GET"

                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "jcr:primaryType"
                    }
                }
            }
    ])

}