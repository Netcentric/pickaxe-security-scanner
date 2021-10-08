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
import biz.netcentric.security.checkerdsl.payload.Credential
import biz.netcentric.security.checkerdsl.payload.FilterEvasion


HttpSecurityCheck.create{

    id "nc-uinfUpkCs"

    name "Userinfo Servlet is exposed"

    vulnerability {
        name "Credential Leakage: ${name}"
        description '''It is possible to harvest valid usernames from jcr:createdBy, jcr:lastModifiedBy, cq:LastModifiedBy attributes of any JCR node which can be used to bruteforce into the system.'''
        remediation "Block access to the affected servlet on publish through AEM dispatcher rules or disable it completely."
        cve "CWE-200"
        severity Severity.HIGH
    }

    categories 'aem-misconfig','dispatcher'

    steps([
            {
                name "GET request to user info servlet was successfully responded."

                paths {
                    ["/libs/cq/security/userinfo", "///libs///cq///security///userinfo"]
                }

                extensions FilterEvasion.JSON_EVASION.getBypasses()

                Credential.getAll().each { cred ->
                    basicAuthentication cred
                }

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "type"
                    }
                }
            }
    ])

}