/*
 *
 *  * (C) Copyright 2020 Netcentric AG.
 *  *
 *  * All rights reserved. This program and the accompanying materials
 *  * are made available under the terms of the Eclipse Public License v1.0
 *  * which accompanies this distribution, and is available at
 *  * http://www.eclipse.org/legal/epl-v10.html
 *
 */
package biz.netcentric.security.scans

import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.CheckExecutionResult
import biz.netcentric.security.checkerdsl.model.ScanContext
import org.junit.Assert
import org.junit.jupiter.api.Test

import static org.mockserver.model.HttpRequest.request
import static org.mockserver.model.HttpResponse.response

class UniCodeBypassCheckTest implements MockServerTrait {

    String CHECK_UNDER_TEST = "misconfiguration/unicode-bypass.groovy"

    @Test
    void "check content grabbing with unicode characters selectors"() {
        HttpSecurityCheck check = loadSingleCheck("nc-UniC7eLvR", CHECK_UNDER_TEST)
        CheckExecutionResult result = check createHttpClient(), new ScanContext("http://localhost:" + DEFAULT_PORT + "/content/de/we-retail.html")

        Assert.assertEquals 1, result.issues.size()
    }

    @Override
    void setExpectations() {
        // the url matches "/content/de/we-retail.١.json"
        // be aware that plain unicode chars are send URL encoded
        mockServerClient()
                .when(
                        request()
                                .withMethod("GET")
                                .withPath("/content/de/we-retail.%D9%A1.json")
                )
                .respond(
                        response()
                                .withBody("{ jcr:createdBy: admin, jcr:lastModifiedBy: admin }")
                )
    }

    @Override
    void resetExpectations() {
        reset("/content/de/we-retail.%D9%A1.json")
    }
}