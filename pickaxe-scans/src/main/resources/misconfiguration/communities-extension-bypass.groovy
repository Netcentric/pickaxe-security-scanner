/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package misconfiguration

import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.payload.Generator

def check = HttpSecurityCheck.create {

    id "nc-thncam33x"

    name "AEM Communities selector and extensions are whitelisted to generously"

    details {
        name "Information Disclosure and Enumeration: ${name}"
        description '''The page is leaking information which is not supposed to be shared with the outside world. AEM's dispatcher must block access to any URL that leaks metadata. Please check the URL's manually.'''
        remediation "Allow only known sling selectors and URL extensions based on on whitelist."
        cve ""
        severity Severity.HIGH
    }

    categories "aem-misconfig", "dispatcher"

    steps([
            {

                name "GET to target URL with AEM communities selectors and extensions"

                extensions {
                    Generator.createUniqueValues(["", ".social.json", ".social.{0}.json"], "{0}", 1)
                }

                method "GET"

                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "jcr:createdBy", "jcr:lastModifiedBy", "rep:principalName", "rep:password", "rep:authorizableId"
                    }
                }
            }]
    )
}

check