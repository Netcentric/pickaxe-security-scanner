/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
import biz.netcentric.security.checkerdsl.model.Severity

def check = HttpSecurityCheck.create {

    id "nc-crxlogsJbp"

    name "CRX logs are exposed"

    details {
        name "Information Disclosure: ${name}"
        description "CRX logs should not be accessible"
        remediation "Block CRX logs access through AEM dispatcher rules."
        cve ""
        severity Severity.HIGH
    }
    steps([
            {
                name "GET to CRX to check if it responds or any crx related tools is accessible"

                categories "crx", "dispatcher"

                paths {
                    ["/bin/crxde/logs{0}?tail=100", "///bin///crxde///logs{0}?tail=100"
                    ]
                }

                extensions {
                    ["", ".json", ".1.json", ".4.2.1...json", ".html", ";%0aa.css", ";%0aa.html",
                     ";%0aa.js","%0aa.ico", ";%0aa.png", "/a.css", "/a.html", "/a.png", "/a.js", "/a.ico"]
                }

                method "GET"

                detect {
                    all{
                        checkStatusCode 200
                        bodyContainsAny "*WARN*", "*INFO*"
                    }
                }
            }
    ])

}

check
