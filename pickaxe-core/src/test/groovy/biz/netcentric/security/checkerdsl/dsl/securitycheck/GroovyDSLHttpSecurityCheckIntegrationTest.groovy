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

class GroovyDSLHttpSecurityCheckIntegrationTest extends MockServer {

    String JSON_RESPONSE = '''
    {
        results:12,
        whatever: [1,2,3]
    }
    '''

    @Test
    void "single rule is evaluated correctly"() {
        AsyncHttpClient httpClient = new AsyncHttpClient()
        def check = createSecurityCheck({
            all {
                checkStatusCode 200
            }
        })

        def result = check httpClient, new ScanContext("http://localhost:" + MockServer.DEFAULT_PORT + "/some-irrelevant-base-url.html")

        Assert.assertEquals 1, result.issues.size()
    }

    @Test
    void "contains an expected response header part"() {
        AsyncHttpClient httpClient = new AsyncHttpClient()
        def check = createSecurityCheck({
            all {
                checkStatusCode 200
                responseHeaderContainsAny "content-type", "application"
            }
        })

        def result = check httpClient, new ScanContext("http://localhost:" + MockServer.DEFAULT_PORT + "/send-response-header.html")

        Assert.assertEquals 1, result.issues.size()
    }

    @Test
    void "response header detected"() {
        AsyncHttpClient httpClient = new AsyncHttpClient()
        def check = createSecurityCheck({
            all {
                checkStatusCode 200
                responseHeaderEqualsAny "content-type", "application/json; charset=utf-8", "application/json"
            }
        })

        def result = check httpClient, new ScanContext("http://localhost:" + MockServer.DEFAULT_PORT + "/send-response-header.html")

        Assert.assertEquals 1, result.issues.size()
    }

    @Test
    void "multiple mandatory rules are evaluated correctly"() {
        AsyncHttpClient httpClient = new AsyncHttpClient()
        def check = createSecurityCheck({
            all {
                checkStatusCode 200
                bodyContains "whatever"
                bodyContains "results"
            }
        })

        def result = check httpClient, new ScanContext("http://localhost:" + MockServer.DEFAULT_PORT + "/some-irrelevant-base-url.html")

        Assert.assertEquals 1, result.issues.size()
    }

    @Test
    void "rule finds an issue"() {
        AsyncHttpClient httpClient = new AsyncHttpClient()
        def check = createSecurityCheck {
            all {
                when "Response contains correct json mimetype and results object", {
                    return true
                }
            }
        }

        def result = check httpClient, new ScanContext("http://localhost:" + MockServer.DEFAULT_PORT + "/some-irrelevant-base-url.html")

        Assert.assertEquals 1, result.issues.size()
    }

    @Test
    void "rule does not find an issue"() {
        AsyncHttpClient httpClient = new AsyncHttpClient()
        def check = createSecurityCheck {
            all {
                when "response does not contain anything", {
                    return false
                }
            }
        }

        def result = check httpClient, new ScanContext("http://localhost:" + MockServer.DEFAULT_PORT + "/some-irrelevant-base-url.html")

        Assert.assertEquals 0, result.issues.size()
    }

    def createSecurityCheck(Closure detectClosure) {
        def check = HttpSecurityCheck.create {
            id "Complex Evaluation rule"
            details {
                name "Information Disclosure"
                description "Complex rule which requires the definition of a closure to eval the result"
                remediation "Block CRX access through AEM dispatcher rules."
                cve ""
                severity Severity.HIGH
            }
            steps(
                    [
                            {
                                paths { '/bin/msm/audit' }
                                extensions {
                                    ['.json']
                                }
                                method "GET"
                                detect detectClosure
                            }]
            )

        }
        check
    }

    @Override
    void setExpectations() {
        mockServerClient()
                .when(
                        request()
                                .withMethod("GET")
                                .withPath("/bin/msm/audit.json")
                )
                .respond(

                        response(JSON_RESPONSE)
                                .withHeader("content-type", "application/json; charset=utf-8")
                                .withHeader("x-frame-options", "SAMEORIGIN")
                )
    }

    @Override
    void resetExpectations() {
        mockServerClient().reset()
    }
}

