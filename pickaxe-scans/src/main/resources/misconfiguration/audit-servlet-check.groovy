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



HttpSecurityCheck.create{

    id "nc-XNBpkC0s"

    name "AEM MsmAuditServlet exposed"

    vulnerability {
        name "Information Disclosure: ${name}"
        description '''AuditServletDetector exposed and might expose audit log information. See https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=96'''
        remediation "Block to the audit servlet on publish through AEM dispatcher rules."
        cve "CWE-668"
        severity Severity.HIGH
    }

    categories 'aem-misconfig','dispatcher'

    steps([
            {
                name "GET request to audit servlet paths"

                paths {
                    ['/bin/msm/audit', '///bin///msm///audit']
                }

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "results"
                    }
                }
            }
    ])

}