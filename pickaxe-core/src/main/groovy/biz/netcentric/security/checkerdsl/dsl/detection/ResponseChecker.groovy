/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.dsl.detection

import biz.netcentric.security.checkerdsl.model.HttpRequestResponse
import groovy.util.logging.Slf4j
import org.apache.commons.lang3.StringUtils

/**
 * Checks an HttpRequestResponse and evaluates if it
 * matches certain expectation criteria concerning the response and/or the body.
 * The expectations can be chained.
 */
@Slf4j
class ResponseChecker {

    HttpRequestResponse httpRequestResponse

    URI target

    String body

    List<DetectionResult> results = []

    ResponseChecker(HttpRequestResponse httpRequestResponse) {
        this.httpRequestResponse = httpRequestResponse
        this.target = httpRequestResponse.getUri()
        this.body = httpRequestResponse.getBody()
    }

    /**
     * Checks a status code
     * @param expectedStatusCode
     */
    void checkStatusCode(int expectedStatusCode) {
        int statusCode = httpRequestResponse.getCode()
        log.debug "Checking statuscode ${statusCode}"

        boolean isMatch = statusCode == expectedStatusCode

        results << new DetectionResult(checkId: "statuscode check", url: target, name: "StatusCode ${expectedStatusCode}", result: isMatch, mandatory: true)
    }

    /**
     * Checks wether all tokens are found
     * @param identifiers
     */
    void bodyContains(String... identifiers) {
        log.debug "Checking if body contains ${identifiers.join(",")}"

        boolean isMatch = false
        List<String> detectedIdentifiers = []
        identifiers.each { identifier ->
            if (this.body.contains(identifier)) {
                isMatch = true
                detectedIdentifiers << identifier
            }
        }
        def showIdentifiers = detectedIdentifiers.size() > 0 ? detectedIdentifiers : identifiers

        results << new DetectionResult(checkId: "body contains check", url: target, name: "bodyContains all of ${showIdentifiers.join('-')}", result: isMatch, mandatory: true)
    }

    /**
     * Checks wether one token is found
     * @param identifiers
     */
    void bodyContainsAny(String... identifiers) {
        log.debug "Checking if body contains ${identifiers.join(",")}"

        List<String> detectedIdentifiers = []
        identifiers.each { identifier ->
            if (this.body.contains(identifier)) {
                detectedIdentifiers << identifier
            }
        }

        boolean isMatch = detectedIdentifiers.size() > 0
        def showIdentifiers = isMatch ? detectedIdentifiers : identifiers

        results << new DetectionResult(checkId: "body contains check", url: target, name: "bodyContains one of ${showIdentifiers.join('-')}", result: isMatch, mandatory: true)
    }

    void when(String expression, Closure customClosure) {
        log.debug "Checking custom closure: ${expression}"
        boolean isMatch = customClosure()
        results << new DetectionResult(checkId: "when rule closure", url: target, name: "Detection Rule Closure: ${expression}", result: isMatch, mandatory: true)
    }

    void responseHeaderEqualsAny(String headerName, String... expected) {
        def headers = this.httpRequestResponse.getResponseHeaders()
        headers.each { header ->
            if (StringUtils.equalsIgnoreCase(headerName, header.getName())) {
                String value = header.getValue()
                boolean isMatch = StringUtils.equalsAnyIgnoreCase(value, expected)
                results << new DetectionResult(checkId: "response header equals any check", url: target, name: "Header [${headerName}: ${expected.join(' | ')}]", result: isMatch, mandatory: true)
            }
        }
    }

    void responseHeaderContainsAny(String headerName, String... expected) {
        def headers = this.httpRequestResponse.getResponseHeaders()
        headers.each { header ->
            if (StringUtils.equalsIgnoreCase(headerName, header.getName())) {
                String value = header.getValue()
                boolean isMatch = StringUtils.containsAny(value, expected)
                results << new DetectionResult(checkId: "response header contains any check", url: target, name: "Header [${headerName}: ${expected.join(' | ')}]", result: isMatch, mandatory: true)
            }
        }
    }

    void responseHeaderIsMissing(String headerName, String... expected) {
        def headers = this.httpRequestResponse.getResponseHeaders()

        if (headers != null && headers.size() > 0) {
            int requiredHeaderValueCounter = 0
            headers.each { header ->
                String value = header.getValue()
                if (StringUtils.containsAny(value, expected)) {
                    requiredHeaderValueCounter++
                }
            }

            boolean isMatch = requiredHeaderValueCounter == 0
            results << new DetectionResult(checkId: "response header missing check", url: target, name: "Required header [${headerName}: with one of the values: ${expected.join(' | ')}] is missing", result: isMatch, mandatory: true)
        } else {
            results << new DetectionResult(checkId: "response header missingcheck", url: target, name: "Header [${headerName}] is not present", result: true, mandatory: true)
        }
    }
}