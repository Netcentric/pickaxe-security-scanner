/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.payload.FilterEvasion

def check = HttpSecurityCheck.create {

    id "nc-etcJ17pac"

    name "ExtTreeServlet is exposed"

    details {
        name "Information Disclosure: ${name}"
        description "Packages and related metainformation under /etc/packages and other paths can be accessed and downloaded as the .ext. selector exposes the ExtTreeServlet."
        remediation "Block access through AEM dispatcher rules. Set permissions accordingly and prevent anonymous access."
        cve "CVE-2016-0957"
        severity Severity.HIGH
    }
    steps([
            {
                name "Folder /etc/package is accessible and can be used as entrypoint to access uploaded content packages."

                categories "crx", "dispatcher"

                paths {
                    ["/etc/cloudservices.ext.json","/etc/rep:policy.ext.json", "/etc/packages.ext.json", "/etc/packages/adobe.ext.json", "/etc/packages/my_packages.ext.json", "/etc/packages/day.ext.json"]
                }

                extensions FilterEvasion.DISPATCHER_BYPASS_EXTENSIONS.getBypasses()

                method "GET"

                detect {
                    all{
                        checkStatusCode 200
                        bodyContainsAny "name", "["
                    }
                }
            }
    ])

}

check
