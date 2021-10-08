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

    id "nc-vZOwFwjN"

    name "Anonymous write access is possible"

    vulnerability {
        name "Broken Access Control: ${name}"
        description '''PostServlet is exposed and anonymous write access is possible. It might be possible to post a stored XSS payload resource with the utilized user.'''
        remediation "Block POST operations with the dispatcher. Do not allow write access for anonymous users."
        cve ""
        severity Severity.HIGH
    }

    categories 'accesscontrol'

    steps([{
               name "Check if UGC is writable"

               method "POST"

               paths {
                   ['/content/test', '/content/*', '/content/usergenerated/test', '/content/usergenerated/*',
                    '/content/usergenerated/etc/commerce/smartlists/xxx', '/content/usergenerated/etc/commerce/smartlists/*',
                    '/apps/test', '/apps/*']
               }

               extensions FilterEvasion.ENUMERATION_EXTENSIONS.bypasses

               body "text/html", "UTF-8", { "jcr:primaryType=nt:unstructured" }

               parameters(["test": "xxsdasd", "Authorization:": "Basic  admin:admin"])

               detect {
                   all {
                       checkStatusCode 200
                       bodyContains "<td>Parent Location</td>"
                   }
               }
           }
    ])
}

check
