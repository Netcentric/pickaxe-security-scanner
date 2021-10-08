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

HttpSecurityCheck.create{

    id "nc-rOU34Y8n"

    name "AEM WCMDebugFilter exposed"

    vulnerability {
        name "Information Disclosure: ${name}"
        description '''Sensitive information might be exposed via AEM 's WCMDebugFilter. It will render a backend interface which provides additional attack surface and might be vulnerable to reflected XSS (CVE-2016-7882). See - https://medium.com/@jonathanbouman/reflected-xss-at-philips-com-e48bf8f9cd3c. Please check the URL's manually.'''
        remediation " Disable the debug filter on production instances. Block to the debug filter servlet on publish through AEM dispatcher rules."
        cve "CWE-668"
        severity Severity.HIGH
    }

    categories 'aem-misconfig','dispatcher'

    steps([
            {
                name "GET top target url with debug filter param"

                paths {
                }

                parameters(["debug": "layout"])

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "<br>cell="
                    }
                }
            }
    ])
}
