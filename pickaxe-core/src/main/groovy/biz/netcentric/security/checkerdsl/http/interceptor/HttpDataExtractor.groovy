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

package biz.netcentric.security.checkerdsl.http.interceptor

import biz.netcentric.security.checkerdsl.http.method.HttpHeader
import biz.netcentric.security.checkerdsl.model.HttpRequestResponse
import groovy.util.logging.Slf4j
import okhttp3.HttpUrl
import okhttp3.Request
import okhttp3.Response
import org.apache.commons.lang3.StringUtils

/**
 * Parses a Request and a response and provides a raw model representation of it which can be used for further analysis.
 */
@Slf4j
class HttpDataExtractor {

    final int MAX_RESPONSE_SIZE = 500

    boolean debugMessages = false

    Response httpResponse

    Request httpRequest

    URI uri

    int code

    String body

    List<HttpHeader> responseHeaders = []

    StringBuilder requestMessageBuilder = new StringBuilder()

    StringBuilder responseMessageBuilder = new StringBuilder()

    /**
     * Creates an {@link biz.netcentric.security.checkerdsl.model.HttpRequestResponse} model.
     * @return HttpRequestResponse
     */
    HttpRequestResponse toHttpRequestResponse() {
        preProcessRequest()
        preProcessResponse()

        if (this.body == null) {
            this.body = StringUtils.EMPTY
        }

        String rawRequest = this.requestMessageBuilder.toString()
        String rawResponse =  this.responseMessageBuilder.toString()
        String trimmedResponse = rawResponse.take(MAX_RESPONSE_SIZE)

        new HttpRequestResponse(
                uri: this.uri,
                code: this.code,
                body: this.body,
                rawRequest: rawRequest,
                rawResponse: rawResponse,
                trimmedResponse: trimmedResponse,
                responseHeaders: this.responseHeaders
        )
    }

    void preProcessRequest() {
        HttpUrl url = this.httpRequest.url()
        this.uri = url.url().toURI()

        //newLine requestMessageBuilder, httpRequest.()
        newLine requestMessageBuilder, "${httpRequest.method()} ${httpRequest.url()}"
        // writes all headers
        httpRequest.headers().each { header ->
            newLine requestMessageBuilder, "${header.getFirst()}: ${header.getSecond()}"
        }

        // writes the body by decoding the entity

        // controllable by a flag as we also need to make it configurable from CLI for individual runs without touching slf4j
        if (debugMessages) {
            log.info "Intercepted request message: " + StringUtils.LF + requestMessageBuilder.toString()
        } else {
            log.debug "Intercepted request message: " + StringUtils.LF + requestMessageBuilder.toString()
        }
    }

    void preProcessResponse() {
        Response workingResponse = this.httpResponse
        String message = workingResponse.body().string()
        this.code = workingResponse.code()
        this.body = StringUtils.isNotEmpty(message) ? message : StringUtils.EMPTY

        newLine responseMessageBuilder, "${workingResponse.code()}"
        workingResponse.headers().each { header ->
            this.responseHeaders.add new HttpHeader(name: header.getFirst(), value: header.getSecond())
            newLine responseMessageBuilder, "${header.getFirst()}: ${header.getSecond()}"
        }

        emptyLine(responseMessageBuilder)
        newLine responseMessageBuilder, this.body

        // controllable by a flag as we also need to make it configurable from CLI for individual runs without touching slf4j
        if (debugMessages) {
            log.info "Intercepted response message: " + StringUtils.LF + responseMessageBuilder.toString()
        } else {
            log.debug "Intercepted response message: " + StringUtils.LF + responseMessageBuilder.toString()
        }
    }

    void newLine(StringBuilder messageBuilder, Object value) {
        messageBuilder.append(value.toString()).append(StringUtils.LF)
    }

    void emptyLine(StringBuilder messageBuilder) {
        messageBuilder.append(StringUtils.LF)
    }
}
