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

import biz.netcentric.security.checkerdsl.http.interceptor.HttpDataExtractor
import biz.netcentric.security.checkerdsl.http.method.HttpRequestModel
import biz.netcentric.security.checkerdsl.model.AuthType
import biz.netcentric.security.checkerdsl.model.AuthenticationConfig
import biz.netcentric.security.checkerdsl.model.HttpRequestResponse
import groovy.util.logging.Slf4j
import okhttp3.*
import org.riversun.okhttp3.OkHttp3CookieHelper

import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Async http client implementation with an internal dependency to OkHttp
 */
@Slf4j
class AsyncHttpClient {

    boolean debugMessages = true

    OkHttp3CookieHelper cookieHelper

    OkHttpClient client

    ConnectionPool connectionPool

    boolean persistCookies = false

    AsyncHttpClient() {
        this.client = new OkHttpClient()
        this.cookieHelper = new OkHttp3CookieHelper()
    }

    AsyncHttpClient(HttpClientConfig httpClientConfig) {
        OkHttpClient.Builder okHttpClientBuilder = new OkHttpClient().newBuilder()

        okHttpClientBuilder.connectTimeout(httpClientConfig.getConnectionTimeoutMs(), TimeUnit.MILLISECONDS)
        okHttpClientBuilder.readTimeout(httpClientConfig.getReadTimeoutMs(), TimeUnit.MILLISECONDS)
        okHttpClientBuilder.writeTimeout(httpClientConfig.getWriteTimeout(), TimeUnit.MILLISECONDS)
        okHttpClientBuilder.followRedirects(httpClientConfig.getFollowRedirects())

        this.connectionPool = httpClientConfig.createConnectionPool()
        okHttpClientBuilder.connectionPool(this.connectionPool)

        AuthenticationConfig authConfig = httpClientConfig.authenticationConfig
        if(authConfig != null && authConfig.getAuthenticationType() == AuthType.SIMPLE){
            okHttpClientBuilder.authenticator(new Authenticator() {
                @Override
                Request authenticate(Route route, Response response) throws IOException {
                    String credential = Credentials.basic(authConfig.getUsername(), authConfig.getPassword());
                    return response.request().newBuilder().header("Authorization", credential).build();
                }
            })
        }

        this.client = okHttpClientBuilder.build()

        log.info("Async Http Client with {} parallel connections configured.", httpClientConfig.getConnectionPoolSize())
        this.cookieHelper = new OkHttp3CookieHelper()
    }

    Optional<HttpRequestResponse> execute(HttpRequestModel httpRequest) {
        List<HttpRequestResponse> responses = this.execute([httpRequest])

        HttpRequestResponse result = null
        if (responses.size() > 0) {
            result = responses.get(0)
        }
        return Optional.ofNullable(result)
    }

    List<HttpRequestResponse> execute(List<HttpRequestModel> httpRequests) {

        if (persistCookies) {
            this.client.cookieJar(cookieHelper.cookieJar())
        }

        // need a concurrent list here as we write into it from multiple threads
        Queue<HttpRequestResponse> results = new ConcurrentLinkedQueue<>()

        int parallelRequests = httpRequests.size()
        final CountDownLatch latch = new CountDownLatch(parallelRequests)

        httpRequests.each { httpRequest ->
            addCookiesToRequest(httpRequest)
            Request request = httpRequest.build()

            Call okCall = client.newCall(request)
            okCall.enqueue(new Callback() {

                void onResponse(Call call, Response response)
                        throws IOException {
                    try {
                        Request calledRequest = call.request()
                        HttpDataExtractor dataRecorder = new HttpDataExtractor(httpRequest: calledRequest, httpResponse: response)
                        HttpRequestResponse requestResponse = dataRecorder.toHttpRequestResponse()
                        results.add requestResponse

                        // we log here with info as this debug flag can be triggered by scan config without having to customize the logger
                        if (debugMessages) {
                            log.info(requestResponse.rawRequest)

                            log.info("Executed request to ${requestResponse.getUri().toString()}")
                            log.info(requestResponse.rawResponse)
                        }
                    } finally {
                        latch.countDown()
                    }
                }

                void onFailure(Call call, IOException e) {
                    String uri = call.request().url().uri().toString()
                    latch.countDown()
                    log.error("Request failed ${uri}", e)
                }
            })
        }

        // need to wait till all responses have executed the callback. Else we do not get the results
        try {
            if (debugMessages) {
                log.info("Waiting for requests to finish. ")
            }

            latch.await()

            if (debugMessages) {
                log.info("All requests finished.")
            }
        } catch (InterruptedException e) {
            log.error("Failed waiting for the CountDownLatch. ", e)
        } finally {

        }

        if (debugMessages) {
            log.info("Executed ${parallelRequests} requests")
        }

        results.toList()
    }

    private List addCookiesToRequest(HttpRequestModel httpRequest) {
        for (entry in httpRequest.getCookies()) {
            this.cookieHelper.setCookie(httpRequest.getUrl(), entry.getKey(), entry.getValue())
        }
    }

    void shutdown() {
        if (this.client != null && this.client.dispatcher() != null) {
            this.client.dispatcher().executorService().shutdownNow()
        }

        if (this.connectionPool != null) {
            this.connectionPool.evictAll()
            this.connectionPool == null
        }

        if (this.client != null && this.client.cache() != null) {
            this.client.cache().close()
        }
    }
}
