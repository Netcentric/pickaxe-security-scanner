/*
 *
 *  * (C) Copyright 2016 Netcentric AG.
 *  *
 *  * All rights reserved. This program and the accompanying materials
 *  * are made available under the terms of the Eclipse Public License v1.0
 *  * which accompanies this distribution, and is available at
 *  * http://www.eclipse.org/legal/epl-v10.html
 *
 */

package biz.netcentric.security.checkerdsl.dsl.securitycheck

import biz.netcentric.security.checkerdsl.MockServer
import biz.netcentric.security.checkerdsl.http.AsyncHttpClient
import biz.netcentric.security.checkerdsl.model.ScanContext
import biz.netcentric.security.checkerdsl.model.Severity
import org.junit.Assert
import org.junit.jupiter.api.Test

import static org.mockserver.model.HttpRequest.request
import static org.mockserver.model.HttpResponse.response

/**
 * This test is supposed to check the behaviour of chained test executions.
 * 1. Check step executes a GET
 * 2. Second executes a POST
 *
 * Both reside in the same test suite
 */
class HttpSecurityCheckMultiStepsIntegrationTest extends MockServer {

    String GET_JSON_RESPONSE = '''
    {
        results:expected_get,
        whatever: [1,2,3]
    }
    '''

    String POST_JSON_RESPONSE = '''
    {
        results:expected_post,
        whatever: [1,2,3]
    }
    '''

    List expectedStepsWithTwoReportableIssues = [
            {
                id "First Evaluation rule"

                paths { '/bin/expect/json' }
                extensions {
                    ['.json']
                }
                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "expected_"
                    }
                }
            },
            {
                id "Second Evaluation rule"
                paths { '/bin/expect/create' }
                extensions {
                    ['.json']
                }
                method "POST"
                detect {
                    all {
                        checkStatusCode 200
                        bodyContains "expected_"
                    }
                }
            }
    ]

    @Test
    void "both detection rules match"() {
        AsyncHttpClient httpClient = new AsyncHttpClient()
        def check = createSecurityCheck(this.expectedStepsWithTwoReportableIssues)

        def result = check httpClient, new ScanContext("http://localhost:" + MockServer.DEFAULT_PORT + "/some-irrelevant-base-url.html")

        Assert.assertEquals 2, result.issues.size()
    }

    @Test
    void "detectionrules match in multistep check from closure"() {
        AsyncHttpClient httpClient = new AsyncHttpClient()
        def check = createSingleSecurityCheckClosure(this.expectedStepsWithTwoReportableIssues)

        def result = check httpClient, new ScanContext("http://localhost:" + MockServer.DEFAULT_PORT + "/some-irrelevant-base-url.html")

        Assert.assertEquals 2, result.issues.size()
    }

    @Test
    void "only one reported issue in multi detection rule match"() {
        AsyncHttpClient httpClient = new AsyncHttpClient()

        // change the initial step and set reportable to false
        List steps = this.expectedStepsWithTwoReportableIssues
        Closure step = steps.get(0) << {reportable(false)}
        List newSteps = [step, steps.get(1)]

        def check = createSecurityCheck(newSteps)

        def result = check httpClient, new ScanContext("http://localhost:" + MockServer.DEFAULT_PORT + "/some-irrelevant-base-url.html")

        Assert.assertEquals 1, result.issues.size()
    }

    def createSecurityCheck(List steps) {
        def check = HttpSecurityCheck.create("multi rule check",
                {
                    name "Information Disclosure"
                    description "Complex rule which requires the definition of a closure to eval the result"
                    remediation "Block CRX access through AEM dispatcher rules."
                    cve ""
                    severity Severity.HIGH
                }, steps)
        check
    }

    def createSingleSecurityCheckClosure(List checkSteps) {
        def httpSecurityCheckClosure = {
            id "nc-id-123"

            details {
                name "Information Disclosure"
                description "Complex rule which requires the definition of a closure to eval the result"
                remediation "Block CRX access through AEM dispatcher rules."
                cve ""
                severity Severity.HIGH
            }

            steps(checkSteps)
        }

        HttpSecurityCheck.create(httpSecurityCheckClosure)
    }

    @Override
    void setExpectations() {
        mockServerClient()
                .when(request()
                                .withPath("/bin/expect/json.json")
                )
                .respond(

                        response(GET_JSON_RESPONSE)
                                .withHeader("content-type", "application/json; charset=utf-8")
                                .withHeader("x-frame-options", "SAMEORIGIN")
                )

        mockServerClient()
                .when(request()
                                .withPath("/bin/expect/create.json")
                )
                .respond(

                        response(POST_JSON_RESPONSE)
                                .withHeader("content-type", "application/json; charset=utf-8")
                                .withHeader("x-frame-options", "SAMEORIGIN")
                )
    }

    @Override
    void resetExpectations() {
        mockServerClient().reset()
    }
}
