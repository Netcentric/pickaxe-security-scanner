/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity

/**
 * Checks if the felix login servlet can be accessed,
 * It will try to probe authentication, but will not report an issue if a login blocks access.
 * TODO: Added more default credentials using the authenticationHeader property and conditional reporting checks
 */
HttpSecurityCheck.create{

    id "nc-QF6uCeYQ"

    name "Exposed Felix Login Servlet"

    vulnerability {
        name "Failure to Restrict URL Access: ${name}"
        description '''The Felix console is exposed. It is an administrative backend which provides full access to the AEM installation and allows to install own code. It can be considered a potential Remote Code Execution vulnerabilty.";"'''
        remediation "Block the path through AEM dispatcher rules. Restrict access completly"
        cve "CWE-749"
        severity Severity.HIGH
    }

    categories 'dispatcher'

    steps([
            {
                name "GET to felix login status endpoints and dispatcher bypasses"

                paths {
                    ['/system/sling/loginstatus', '///system///sling///loginstatus']
                }

                extensions {
                    ['', '١.json']
                }

                header "Authorization", "Basic YWRtaW46YWRtaW4="

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "authenticated"
                    }
                }
            }
    ])

}