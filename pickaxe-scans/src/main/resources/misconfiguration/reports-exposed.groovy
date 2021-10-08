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

    id "nc-uinfUpkCs"

    name "AEM Reports exposed"

    vulnerability {
        name "Information Leakage: ${name}"
        description '''AEM report are exposed and can be called. Despite providing internal information report generation can be considered expensive.'''
        remediation "Block access to the affected url on publish through AEM dispatcher rules or disable it completely."
        cve "CWE-668"
        severity Severity.HIGH
    }

    categories 'aem-misconfig','dispatcher'

    steps([
            {
                name "GET request to user info servlet was successfully responded."

                paths {
                    ["/etc/reports/diskusage.html", "///etc/reports///diskusage.html"]
                }

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "Disk Usage"
                    }
                }
            }
    ])

}