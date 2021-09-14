import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity

/**
 * Checks for the existence of of the felix system console.
 * It will try to probe access, but will not report an issue if a login blocks access.
 */
HttpSecurityCheck.create{

    id "nc-wMGJvmKd"

    name "cqactions servlet exposed"

    vulnerability {
        name "Potential Information leakage: ${name}"
        description '''The CQActionsServlet is exposed an allows to leak information about access rights and the repository structure. It can be used to bypass dispatcher filters for content grabbing.'''
        remediation "Block the CQActionsServlet or disable it"
        cve "CWE-749"
        severity Severity.HIGH
    }

    categories 'dispatcher'

    steps([
            {
                name "GET to cqactions servlets"

                paths {
                    ['/.cqactions.json?authorizableId=anonymous&predicate=useradmin&depth=0&path=/content&_charset_=utf8',
                     '/.cqactions.json?authorizableId=everyone&predicate=useradmin&depth=0&path=/&_charset_=utf8',
                     '/.cqactions.json'
                    ]
                }

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "entries"
                    }
                }
            }
    ])


}