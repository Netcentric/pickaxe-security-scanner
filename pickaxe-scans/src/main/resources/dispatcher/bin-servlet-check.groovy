/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package dispatcher

import biz.netcentric.security.checkerdsl.payload.FilterEvasion

def check = HttpSecurityCheck.create {

    id "nc-XjJ17Jbp"

    name "Servlet Endpoint /bin exposed"

    vulnerability {
        name "Information Disclosure: ${name}"
        description '''Sensitive information might be exposed via AEM\\'s /bin servlet endpoint. '''
        remediation "Block the path through AEM dispatcher rules. Restrict access completly."
        cve "CWE-200"
        severity Severity.HIGH
    }

    steps([
            {
                name "GET requests to /bin using dispatcher bypasses"

                categories 'dispatcher'

                method "GET"

                paths {
                    ['/bin', '/bin.infinity', '/bin.childrenlist', '/bin.harray', '/bin.forms', '/bin.children']
                }

                extensions {
                    ["", ".json", ".1.json", ".json/.a.1.json", ".json/a.4.2.1...json",
                     ".json///.a.1.json", ".json///a.4.2.1...json",
                     ".json/a.css", ".json/a.js", ".json/a.html", ".json/a.ico", ".json/a.png",
                     ".json///a.css", ".json///a.js", ".json///a.html", ".json///a.ico", ".json///a.png",
                     ".json;%0aa.css", ".json;%0aa.html", ".json;%0aa.js", ".json;%0aa.png", ".json;%0aa.ico", "-1..json"]
                }

                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "jcr:primaryType"
                    }
                }
            }
    ])

}

check
