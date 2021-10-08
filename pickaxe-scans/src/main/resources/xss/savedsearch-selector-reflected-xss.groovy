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
 * Checks wether AEM saved search selector triggered error page reflects the path parameter into a link which is reflected XSS triggering on click in the context of the target website.
 */
HttpSecurityCheck.create{

    id "nc-I43wlg6M"

    name "Reflected XSS on savedsearch selector error page"

    vulnerability {
        name "XSS: ${name}"
        description '''Checks wether AEM saved search selector triggered error page reflects the path parameter into a link which is reflected XSS triggering on click in the context of the target website'''
        remediation "Overwrite the actual error page and do not reflect any inputs in there."
        cve ""
        severity Severity.HIGH
    }

    categories 'xss', 'dispatcher'

    steps([
            {
                name "Inject payload into savedsearch selector error page and flip mimetype"

                paths {
                    ["/etc/designs/anythinghere.savedsearch.html"]
                }

                parameters(["path": "javascript:alert(42)///"])

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        responseHeaderContainsAny "content-type", "text/html"
                        bodyContains "href=\"javascript:alert(42)"
                    }
                }
            }
    ])
}