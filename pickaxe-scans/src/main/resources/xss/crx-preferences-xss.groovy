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
import biz.netcentric.security.checkerdsl.payload.FilterEvasion

/**
 * Checks wether AEM saved search selector triggered error page reflects the path parameter into a link which is reflected XSS triggering on click in the context of the target website.
 */
HttpSecurityCheck.create {

    id "nc-I56crx6W"

    name "Reflected XSS in crx setPreferences"

    vulnerability {
        name "XSS: ${name}"
        description """Checks wether setPreferences in /crx/de is accessible and can be used to trigger a reflected XSS. 
Provoking an error when calling the preferences dialog directly causes an XSS in the error page."""
        remediation "Update AEM to the most recent version and use a custom error page for errors coming back from CRX"
        cve ""
        severity Severity.HIGH
    }

    categories 'xss', 'crx'

    steps([
            {
                name "Inject payload into keymap property and provoke a 400 error."

                paths {
                    ["/crx/de/setPreferences.jsp", "///crx///de///setPreferences.jsp"]
                }

                extensions FilterEvasion.HTML_DISPATCHER_BYPASS_EXTENSIONS.getRandomizedBypasses(9)

                parameters(["keymap": "<azgqr>", "language": "0"])

                method "GET"
                detect {
                    all {
                        checkStatusCode 400
                        bodyContains "<azgqr>"
                    }
                }
            }
    ])
}