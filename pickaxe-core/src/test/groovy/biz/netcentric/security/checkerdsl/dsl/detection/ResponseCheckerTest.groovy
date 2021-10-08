/*
 *
 *  * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *  *
 *  * All rights reserved. This program and the accompanying materials
 *  * are made available under the terms of the Eclipse Public License v1.0
 *  * which accompanies this distribution, and is available at
 *  * http://www.eclipse.org/legal/epl-v10.html
 *
 */
package biz.netcentric.security.checkerdsl.dsl.detection

import biz.netcentric.security.checkerdsl.model.HttpRequestResponse
import org.junit.Assert
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class ResponseCheckerTest {

    String DEFAULT_URI = "http://example.com/somepath"

    String BODY = "{jcr:primaryType: 'nt:unstructured', 'results': '0'}"

    ResponseChecker responseChecker

    HttpRequestResponse httpRequestResponse

    @BeforeEach
    void beforeEach(){
        this.httpRequestResponse = new HttpRequestResponse(uri: new URI(DEFAULT_URI), body: BODY)
    }

    @Test
    void checkStatusCodeIsValidTest() {
        this.httpRequestResponse.setCode(200)
        this.responseChecker = new ResponseChecker(this.httpRequestResponse)

        this.responseChecker.checkStatusCode(200)
        Assert.assertTrue this.responseChecker.getResults().get(0).getResult()
    }

    @Test
    void bodyContainsTest() {
        this.responseChecker = new ResponseChecker(this.httpRequestResponse)
        this.responseChecker.bodyContains("nt:unstructured", "results")
        Assert.assertTrue this.responseChecker.getResults().get(0).getResult()
    }

    @Test
    void bodyContainsNegativeMatchTest() {
        this.responseChecker = new ResponseChecker(this.httpRequestResponse)
        this.responseChecker.bodyContains("cq:Page", "author")
        Assert.assertFalse this.responseChecker.getResults().get(0).getResult()
    }

    @Test
    void bodyContainsAnyMatchTest() {
        this.responseChecker = new ResponseChecker(this.httpRequestResponse)
        this.responseChecker.bodyContains("not there","negative","", "nt:unstructured")
        Assert.assertTrue this.responseChecker.getResults().get(0).getResult()
    }

    @Test
    void evaluateClosurePositiveTest() {
        this.responseChecker = new ResponseChecker(this.httpRequestResponse)
        this.responseChecker.when("detectCrxDe", {
            return true
        })
        Assert.assertTrue this.responseChecker.getResults().get(0).getResult()
    }
}
