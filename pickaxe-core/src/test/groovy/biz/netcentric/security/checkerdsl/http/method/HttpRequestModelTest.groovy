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

package biz.netcentric.security.checkerdsl.http.method

import okhttp3.Request
import org.junit.Assert
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class HttpRequestModelTest {

    String BASE_URL = "http://www.example.org/content/sites/home.html"

    String BODY = "<html><head>Head</head><body>Body</body></html>"

    String MIME = "text/html"

    HttpRequestModel httpRequest

    @BeforeEach
    void beforeEach(){
        this.httpRequest = new HttpRequestModel(url: BASE_URL)
    }

    @Test
    void "build plain Request"(){
        Request request = this.httpRequest.build()
        Assert.assertEquals BASE_URL, request.url().toString()
    }

    @Test
    void "build Request with params"(){
        Map params = [:]
        params.put "param1", "value1"
        params.put "param2", "value2"
        params.put "param3", ""
        params.put "param4", ""

        this.httpRequest.setParams(params)

        Request request = this.httpRequest.build()
        Assert.assertEquals BASE_URL + "?param1=value1&param2=value2&param3=&param4=", request.url().toString()
    }

    @Test
    void "build Request with querystring and params"(){
        Map params = [:]
        params.put "param1", "value1"
        params.put "param2", "value2"
        this.httpRequest.setParams(params)
        this.httpRequest.setQueryString("qs=qv&qx=qv2")

        Request request = this.httpRequest.build()
        Assert.assertEquals BASE_URL + "?qs=qv&qx=qv2&param1=value1&param2=value2", request.url().toString()
    }

    @Test
    void "build Request with body"(){
        this.httpRequest.setBody {
            return BODY
        }

        this.httpRequest.setMethod(HttpMethod.POST.name)
        this.httpRequest.setBodyType(MIME)

        Request request = this.httpRequest.build()

        Assert.assertNotNull request.body()
    }

    @Test
    void "build Request with empty body when GET"(){
        this.httpRequest.setBody {
            return BODY
        }
        this.httpRequest.setBodyType(MIME)

        Request request = this.httpRequest.build()
        Assert.assertNull request.body()
    }
}
