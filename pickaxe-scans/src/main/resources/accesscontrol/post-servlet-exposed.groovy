/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
import biz.netcentric.security.checkerdsl.payload.FilterEvasion

def check = HttpSecurityCheck.create {

    id "nc-DnrZ3xas"

    name "PostServlet writes to DAM"

    vulnerability {
        name "Broken Access Control: ${name}"
        description '''PostServlet is exposed. It might be possible to use it for posting a stored XSS payload.'''
        remediation "Block POST operations with the dispatcher. Do not allow write access for anonymous users."
        cve ""
        severity Severity.HIGH
    }

    categories 'accesscontrol'

    steps([
            {
                name "Check if content tree is writable using dispatcher bypasses"

                method "POST"

                paths {
                    ['/', '/content', '/content/dam']
                }

                // we do not set referer as our post method is setting it implicitly
                headers(["Content-Type": "application/x-www-form-urlencoded"])

                parameters([":operation": "nop"])

                extensions FilterEvasion.ENUMERATION_EXTENSIONS.bypasses

                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "Null Operation Status:"
                    }
                }
            }
    ])
}

check
