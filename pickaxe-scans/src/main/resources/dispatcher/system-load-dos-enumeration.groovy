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
import biz.netcentric.security.checkerdsl.payload.FilterEvasion

HttpSecurityCheck.create{

    id "nc-Ow67Lufxx"

    name "Denial of Service possible through children enumeration selector"

    vulnerability {
        name "Denial of Service: ${name}"
        description '''Calling any URL with the supplied pattern /......children.-1.... in combination with a a dispatcher bypass will 
        cause an infinte traversal of the page tree starting from the actual entrypoint. Therefore it must be appended to an existing URL. 
        '''
        remediation "Block the pattern *.children.-{0-9}*. selector via WAF, proxy  or dispatcher rule and harden dispatcher against other bypasses."
        cve "CWE-668"
        severity Severity.HIGH
    }

    categories 'dispatcher', 'dos'

    steps([
            {
                name "GET children and negative increment selector to cause children enumeration to put load on the system"

                paths {
                }

                // TODO: this check is temporarily downgraded to .1. as with the new URL handling it has become too expensive to run with no path
                // The finding is still valid
                def prefix = ["/a.js/......children....1....json", "/......children....1....json"]
                extensions FilterEvasion.DISPATCHER_BYPASS_EXTENSIONS.prefixBypasses(prefix)

                method "GET"

                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "jcr:primaryType"
                    }
                }
            }
    ])

}