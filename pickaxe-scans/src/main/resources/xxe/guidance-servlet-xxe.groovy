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
import biz.netcentric.security.checkerdsl.payload.Generator

/**
 * Based on https://github.com/0ang3el/aem-hacker/blob/master/aem_hacker.py
 * We do not try to exploit it but check wether the endpoint is accessible for the outside world. This should be enough.
 */
HttpSecurityCheck.create{

    id "nc-xgxxe4gH"

    name "XXE vulnerability in AEM Forms Guidance Servlet"

    vulnerability {
        name "XXE: ${name}"
        description """GuideInternalSubmitServlet is exposed, XXE is possible."""
        remediation """Update AEM to the most recent version. Block access to the .af. selector if not explicitly needed for any AEM Forms use cases as it exposes a number of vulnerabilities. 
If really needed allow only for distinct paths and avoid restrict the ability to create create and edit nodes as it is possible to trigger the servlet by sling:resourceType"""

        cve ""
        severity Severity.HIGH
    }

    categories "xxe", "dispatcher"

    steps([
            {

                name "GuideInternalSubmitServlet is exposed, XXE is possible."

                method "POST"

                // we do not set referer as our post method is setting it implicitly
                headers(["Content-Type": "application/x-www-form-urlencoded"])

                paths {
                    ["/content/forms/af/geometrixx-gov/application-for-assistance/jcr:content/guideContainer",
                     "/content/forms/af/geometrixx-gov/geometrixx-survey-form/jcr:content/guideContainer",
                     "/content/forms/af/geometrixx-gov/hardship-determination/jcr:content/guideContainer",
                     "/libs/fd/af/components/guideContainer/cq:template",
                     "///libs///fd///af///components///guideContainer///cq:template",
                     "/libs/fd/af/templates/simpleEnrollmentTemplate2/jcr:content/guideContainer",
                     "///libs///fd///af///templates///simpleEnrollmentTemplate2///jcr:content///guideContainer",
                     "/libs/fd/af/templates/surveyTemplate2/jcr:content/guideContainer",
                     "///libs///fd///af///templates///surveyTemplate2///jcr:content///guideContainer",
                     "/libs/fd/af/templates/blankTemplate2/jcr:content/guideContainer",
                     "///libs///fd///af///templates///blankTemplate2///jcr:content///guideContainer",
                     "/libs/fd/af/templates/surveyTemplate/jcr:content/guideContainer",
                     "/libs/fd/af/templates/surveyTemplate/jcr:content/guideContainer",
                     "///libs///fd///af///templates///surveyTemplate///jcr:content///guideContainer",
                     "/libs/fd/af/templates/tabbedEnrollmentTemplate/jcr:content/guideContainer",
                     "///libs///fd///af///templates///tabbedEnrollmentTemplate///jcr:content///guideContainer",
                     "/libs/fd/af/templates/tabbedEnrollmentTemplate2/jcr:content/guideContainer",
                     "///libs///fd///af///templates///tabbedEnrollmentTemplate2///jcr:content///guideContainer",
                     "/libs/fd/af/templates/simpleEnrollmentTemplate/jcr:content/guideContainer",
                     "///libs///fd///af///templates///simpleEnrollmentTemplate///jcr:content///guideContainer",
                     "/libs/settings/wcm/template-types/afpage/initial/jcr:content/guideContainer",
                     "///libs///settings///wcm///template-types///afpage///initial///jcr:content///guideContainer",
                     "/libs/settings/wcm/template-types/afpage/structure/jcr:content/guideContainer",
                     "///libs///settings///wcm///template-types///afpage///structure///jcr:content///guideContainer",
                     "/apps/geometrixx-gov/templates/enrollment-template/jcr:content/guideContainer",
                     "/apps/geometrixx-gov/templates/survey-template/jcr:content/guideContainer",
                     "/apps/geometrixx-gov/templates/tabbed-enrollment-template/jcr:content/guideContainer"
                     ]
                }

                def fileExtensions  = [
                        ".af.internalsubmit.json", ".af.internalsubmit.1.json", ".af.internalsubmit...1...json",
                        ".af.internalsubmit.html", ".af.internalsubmit.js", ".af.internalsubmit.css",
                        ".af.internalsubmit.ico", ".af.internalsubmit.png", ".af.internalsubmit.gif",
                        ".af.internalsubmit.svg", ".af.internalsubmit.ico;%0a{0}.ico",
                        ".af.internalsubmit.html;%0a{0}.html", ".af.internalsubmit.css;%0a{0}.css"]

                extensions Generator.createUniqueValues(fileExtensions, "{0}", 4)

                body "application/json", "UTF-8", { 'guideState={"guideState"%3a{"guideDom"%3a{},"guideContext"%3a{"xsdRef"%3a"","guidePrefillXml"%3a"<afData>\u0041\u0042\u0043</afData>"}}}'}

                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "<afData>ABC"
                    }
                }
            }
    ])
}