import biz.netcentric.security.checkerdsl.payload.FilterEvasion

def check = HttpSecurityCheck.create {

    id "nc-AVySnyIS"

    name "AEM WCMSuggestionsServlet exposed"

    vulnerability {
        name "Information Disclosure: ${name}"
        description '''WCMSuggestionsServlet exposed and might result in reflected XSS. See - https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=96'''
        remediation " Disable the debug servlet on production instances. Block to the debug servlet path on publish through AEM dispatcher rules."
        cve "CWE-668"
        severity Severity.HIGH
    }

    categories 'aem-misconfig','dispatcher'

    steps([
            {
                name "GET to contentfinder's suggestions servlet"

                method "GET"

                paths {
                    ["/bin/wcm/contentfinder/connector/suggestions", "///bin///wcm///contentfinder///connector///suggestions"]
                }

                parameters(["query_term":"path%3a/", "pre":"<1337abcdef>", "post": "yyyy"])

                extensions FilterEvasion.ENUMERATION_EXTENSIONS.bypasses

                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "<1337abcdef>"
                    }
                }
            }
    ])
}

check
