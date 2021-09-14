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

package biz.netcentric.security.checkerdsl.http.method

import biz.netcentric.security.checkerdsl.payload.Encoding
import groovy.util.logging.Slf4j
import io.mikael.urlbuilder.UrlBuilder
import io.mikael.urlbuilder.util.UrlParameterMultimap
import okhttp3.MediaType
import okhttp3.Request
import okhttp3.RequestBody
import org.apache.commons.lang3.StringUtils

/**
 * HttpRequestModel which serves for config data abstraction purposes.
 *
 * TODO: Support for
 * - file transfer
 * - form submission
 */
@Slf4j
class HttpRequestModel {

    String url

    String queryString

    Map<String, Object> params = [:]

    List<HttpHeader> authenticationHeaders = []

    Map<String, Object> requestHeaders = [:]

    Map<String, Object> cookies = [:]

    Closure<String> body

    String bodyType

    String bodyEncoding

    String method

    Request build() {

        if (this.method == null) {
            this.method = HttpMethod.GET.name()
        }

        String url = createUrl()

        log.debug "URL Mutation: " + url

        Request.Builder requestBuilder = new Request.Builder()
                .url(url)

        this.authenticationHeaders.each { authHeader ->
            requestBuilder.header(authHeader.getName(), authHeader.getValue())
        }

        this.requestHeaders.each { name, value ->
            requestBuilder.header(name, value)
        }

        if (HttpMethod.POST.isMethod(this.method) ||
                HttpMethod.PUT.isMethod(this.method) ||
                HttpMethod.PATCH.isMethod(this.method)) {

            String requestBody = this.body()
            if (requestBody?.trim()) {
                addRequestBody(requestBuilder, this.bodyType, requestBody)
            }
        }

        requestBuilder.build()
    }

    private String createUrl() {
        UrlParameterMultimap parameters = this.extractParametersFromQueryString()

        this.params.each { name, value ->
            // do check as we might have named properties without a value
            String val = StringUtils.isNotBlank(value) ? value : StringUtils.EMPTY
            parameters.add(name, val)
        }

        UrlBuilder.fromString(this.url)
                .withParameters(parameters)
                .toString()
    }

    private UrlParameterMultimap extractParametersFromQueryString() {
        UrlParameterMultimap parameters = UrlParameterMultimap.newMultimap()
        // join queryStrings if the URL contains one already.
        // for simplicity reasons we allow to add one to the url as well.
        // in this case we should join the queryString param with it.
        if(this.url.contains("?")){
            def queryStringFromUrl = StringUtils.substringAfter(this.url, "?")

            if(StringUtils.isNotBlank(queryString) && StringUtils.isNotBlank(queryStringFromUrl)){
                this.queryString = queryStringFromUrl + "&" + queryString
            }else{
                this.queryString = queryStringFromUrl
            }
        }

        // now we process the querystring
        if (StringUtils.isNotBlank(this.queryString)) {
            String[] params = queryString.split("&")
            params.each { param ->
                String[] keyValuePair = param.split("=", 2)
                String name = URLDecoder.decode(keyValuePair[0], Encoding.UTF8)
                if (StringUtils.isNotEmpty(name)) {
                    String value = keyValuePair.length > 1 ? URLDecoder.decode(keyValuePair[1], Encoding.UTF8) : StringUtils.EMPTY;
                    parameters.add(name, value)
                }
            }
        }

        parameters
    }

    void addRequestBody(Request.Builder builder, String bodyType, String body) {
        MediaType mediaType = MediaType.get(bodyType)
        RequestBody requestBody = RequestBody.create(body, mediaType)

        builder.method(this.method, requestBody)
    }
}
