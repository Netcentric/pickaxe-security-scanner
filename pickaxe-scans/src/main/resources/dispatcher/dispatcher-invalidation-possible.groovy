/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.payload.Generator

def check = HttpSecurityCheck.create {

    id "nc-disJ17inv"

    name "Dispatcher invalidation is unprotected"

    details {
        name "Denial of Service: ${name}"
        description "Dispatchers can be invalidated from an untrusted external system. This would allow an attacker render the caching layer completely useless and force the AEM publishing instances to handle all incoming load."
        remediation "Do not allow invalidation from any untrusted source. Block access to the URls and introduce authentication and/or IP whitelisting."
        cve ""
        severity Severity.HIGH
    }
    steps([
            {
                name "The /dispatcher/invalidate.cache must not be exposed."

                categories "crx", "dispatcher"

                def baseInvalidationPath = "/dispatcher/invalidate.cache"
                def preparedPaths = ["${baseInvalidationPath}", "/{0}${baseInvalidationPath}", "${baseInvalidationPath}.{0}", "/{0}${baseInvalidationPath}.{0}" ]

                paths {
                    Generator.createUniqueValues(preparedPaths, "{0}", 3)
                }

                headers(["CQ-Action": "Activate", "CQ-Handle": "/content", "Content-Length": "0", "Content-Type": "application/octet-stream"])

                method "GET"

                detect {
                    all{
                        checkStatusCode 200
                        bodyContainsAny "OK", "<h1>"
                    }
                }
            }]
    )
}

check