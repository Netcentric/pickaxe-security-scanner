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

    id "nc-xxe324Jbp"

    name "XXE via Webdav in Jackrabbit"

    details {
        name "XXE: ${name}"
        description "XML external entity (XXE) vulnerability in Apache Jackrabbit before 2.10.1 allows remote attackers to read arbitrary files and send requests to intranet servers via a crafted WebDAV request. "
        remediation "Disable webdav on the affected instance or install the respective fix."
        cve "CVE-2015-1833"
        severity Severity.HIGH
    }
    steps([
            {
                name "POST request to Webdav Endpoint"

                categories "crx", "webdav"

                paths {
                    ["/crx/repository/test.sh"]
                }

                extensions {
                    ["", ".json", ".css", ".js", ".html", ".ico", ".png", ".gif",
                     ";%0aa.css", ";%0aa.js", ";%0aa.html", ";%0aa.ico", ";%0aa.png",
                     "/a.css", "/a.html", "/a.js", "/a.ico", "/a.png", "/a.ico"]
                }

                method "POST"

                detect {
                    all {
                        checkStatusCode 401
                        bodyContainsAny "WWW-Authenticate:"
                    }

                    all {
                        bodyContainsAny "http://www.day.com/jcr/webdav/1.0"
                    }
                }
            }
    ])

}

check