/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package dispatcher

import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.payload.FilterEvasion

/**
 * Will try a number of well known paths and filter evasion extensions to bypass the dispatcher rules which protect the querybuilder.
 * Querybuilder might be an entrypoint to either gathe rinformation or to put load on the system.
 */
HttpSecurityCheck.create{

    id "nc-s55ibLtb"

    name "Querybuilder Exposed"

    vulnerability {
        name "Information Disclosure: ${name}"
        description '''Sensitive information might be exposed via AEMs QueryBuilderServlet or QueryBuilderFeedServlet. Be aware that bypasses using image/* mimetype extensions e.g. *.ico may render in a browser as an image but if you rename the file with the ending *.txt you will see the querybuilder output'''
        remediation '''Block the path through AEM dispatcher rules. Restrict access completly.'''
        cve "CWE-749"
        severity Severity.HIGH
    }

    categories 'dispatcher'


    steps([
            {
                name "GET to querybuilder using dispatcher bypasses"

                paths {
                    ["/bin/querybuilder.json", "/bin/querybuilder.json.servlet",
                     "///bin///querybuilder.json", "///bin///querybuilder.json.servlet",
                     "/bin/querybuilder.feed", "/bin/querybuilder.feed.servlet",
                     "///bin///querybuilder.feed", "///bin///querybuilder.feed.servlet"]
                }

                extensions FilterEvasion.DISPATCHER_BYPASS_EXTENSIONS.bypasses

                method "GET"

                // checks wether we get a response allows the conclusion that querybuilder is responding
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "hits", "<feed>"
                    }
                }
            }
    ])

}