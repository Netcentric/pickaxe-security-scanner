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

package biz.netcentric.security.checkerdsl.http

import biz.netcentric.security.checkerdsl.MockServer
import biz.netcentric.security.checkerdsl.http.method.HttpRequestModel
import biz.netcentric.security.checkerdsl.model.HttpRequestResponse
import org.junit.Assert
import org.junit.jupiter.api.Test

import static org.mockserver.model.HttpRequest.request
import static org.mockserver.model.HttpResponse.response

class AsyncHttpClientTest extends MockServer {

    String JSON_RESPONSE = '''
    {
        results:12,
        whatever: [1,2,3]
    }
    '''

    @Test
    void "execute GET request"() {
        HttpRequestModel httpRequest = new HttpRequestModel(url: "http://localhost:${DEFAULT_PORT}/get.json", method: "GET")
        AsyncHttpClient asyncHttpClient = new AsyncHttpClient()
        List<HttpRequestResponse> results = asyncHttpClient.execute([httpRequest])

        Assert.assertEquals 200, results.get(0).getCode()
        Assert.assertTrue results.get(0).getBody().contains("[1,2,3]")
    }

    @Test
    void "execute multiple GET request"() {
        List<HttpRequestModel> requests = []
        requests.add new HttpRequestModel(url: "http://localhost:${DEFAULT_PORT}/get.json", method: "GET")
        requests.add new HttpRequestModel(url: "http://localhost:${DEFAULT_PORT}/get1.json", method: "GET")
        requests.add new HttpRequestModel(url: "http://localhost:${DEFAULT_PORT}/get2.json", method: "GET")

        AsyncHttpClient asyncHttpClient = new AsyncHttpClient()
        List<HttpRequestResponse> results = asyncHttpClient.execute(requests)

        results.each { result ->
            Assert.assertEquals 200, result.getCode()
            Assert.assertTrue result.getBody().contains("[1,2,3]")
        }
    }

    @Test
    void "execute POST request"() {
        HttpRequestModel httpRequest = new HttpRequestModel(url: "http://localhost:${DEFAULT_PORT}/get.json", method: "POST")
        httpRequest.setBody { return JSON_RESPONSE }
        httpRequest.setBodyType("application/json")
        AsyncHttpClient asyncHttpClient = new AsyncHttpClient()
        List<HttpRequestResponse> results = asyncHttpClient.execute([httpRequest])

        Assert.assertEquals 200, results.get(0).getCode()
        Assert.assertTrue results.get(0).getBody().contains("[1,2,3]")
    }

    @Test
    void "execute failing POST request"() {
        HttpRequestModel httpRequest = new HttpRequestModel(url: "http://localhost:${DEFAULT_PORT}/doesnotexist.json", method: "POST")
        httpRequest.setBody { return JSON_RESPONSE }
        httpRequest.setBodyType("application/json")
        AsyncHttpClient asyncHttpClient = new AsyncHttpClient()

        List<HttpRequestResponse> results = asyncHttpClient.execute([httpRequest])

        Assert.assertEquals 404, results.get(0).getCode()
    }

    @Override
    void setExpectations() {
        mockServerClient()
                .when(request()
                        .withPath("/get.json")
                )
                .respond(response(JSON_RESPONSE)
                        .withStatusCode(200)
                        .withHeader("content-type", "application/json; charset=utf-8")
                )

        mockServerClient()
                .when(request()
                        .withPath("/get1.json")
                )
                .respond(response(JSON_RESPONSE)
                        .withStatusCode(200)
                        .withHeader("content-type", "application/json; charset=utf-8")
                )

        mockServerClient()
                .when(request()
                        .withPath("/get2.json")
                )
                .respond(response(JSON_RESPONSE)
                        .withStatusCode(200)
                        .withHeader("content-type", "application/json; charset=utf-8")
                )
    }

    @Override
    void resetExpectations() {
        mockServerClient().reset()
    }
}