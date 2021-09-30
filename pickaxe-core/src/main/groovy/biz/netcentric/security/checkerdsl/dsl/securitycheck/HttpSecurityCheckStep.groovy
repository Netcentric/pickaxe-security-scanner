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

import biz.netcentric.security.checkerdsl.dsl.detection.DetectionRule
import biz.netcentric.security.checkerdsl.dsl.generator.UrlGenerator
import biz.netcentric.security.checkerdsl.http.method.HttpHeader
import biz.netcentric.security.checkerdsl.http.method.HttpRequestModel
import biz.netcentric.security.checkerdsl.model.HttpRequestResponse
import biz.netcentric.security.checkerdsl.model.VulnerabilityDescription
import biz.netcentric.security.checkerdsl.payload.Credential
import groovy.util.logging.Slf4j
import org.apache.commons.lang3.StringUtils

/**
 * Describes an execution step for a scan. May have successors, which are required to deliver a certain result before a step get's executed.
 * This is defined through a precondition.
 * A step may produce a non reportable issue which is only used to be evaluated by the following step.
 */
@Slf4j
class HttpSecurityCheckStep {

    String id

    String name

    String method

    boolean reportable = true

    def paths = []

    def selectors = []

    def extensions = []

    def suffixes = []

    def bypasses = []

    def querystrings = []

    Map<String, Object> params = [:]

    Map<String, Object> requestHeaders = [:]

    List<HttpHeader> authenticationHeaders = []

    Map<String, Object> authenticationCookies = [:]

    Closure<String> requestBody

    String bodyType

    String bodyEncoding

    Closure<VulnerabilityDescription> vulnerabilityDescription

    Closure<DetectionRule> detectionRule

    Closure requestConfigClosure

    /**
     * Creates a {@link HttpSecurityCheckStep} based on a Closure
     *
     * @param script Closure
     * @return HttpSecurityCheckStep
     */
    static HttpSecurityCheckStep create(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = HttpSecurityCheckStep) Closure script) {
        HttpSecurityCheckStep securityCheckSpec = new HttpSecurityCheckStep()
        script.setDelegate(securityCheckSpec)
        script.resolveStrategy = Closure.DELEGATE_FIRST
        script()

        securityCheckSpec
    }

    /**
     * Creates a list of {@link HttpRequestModel}s for the provided URLs
     *
     * @param targetURL Target URL of the scan
     * @param contentUrls Additional content URLs associated with the target
     * @return List of HttpRequestModels
     */
    List<HttpRequestModel> preparedRequestModels(URL targetURL, List<URL> contentUrls) {
        List<HttpRequestModel> preparedRequests = []
        Set<URL> urlMutations = this.createUrlMutations(targetURL, contentUrls)
        urlMutations.each { urlMutation ->
            List<String> queryStrings = getQuerystrings()
            if (queryStrings.size() > 0) {
                queryStrings.each { queryString ->
                    preparedRequests.addAll this.prepareRequests(urlMutation, queryString)
                }
            } else {
                preparedRequests.addAll this.prepareRequests(urlMutation, StringUtils.EMPTY)
            }
        }

        preparedRequests
    }

    /**
     * URL mutation work which created all combinations of URLS for a paths and the content urls
     * @param targetURL The mandatory target URL
     * @param contentUrls Optional content URLs
     * @return
     */
    List<URL> createUrlMutations(URL targetURL, List<URL> contentUrls) {
        List<URL> urlMutations = []

        // first get all endpoint paths e.g. for a specific servlet or admin interface or
        // statically defined content paths as an alternative e.g. the initial target URL
        List<String> pathsToProcess = this.retrieveStaticEndpointOrContentPaths(targetURL, contentUrls, this.paths)

        // Mutates the provided paths based on the step configuration
        // mutateSlash is currently disabled ... supported in the future
        UrlGenerator generator = new UrlGenerator(
                selectors: this.selectors,
                extensions: this.extensions,
                suffixes: this.suffixes,
                bypasses: this.bypasses,
                mutateSlash: false)


        // now all paths are processed and mutated with the properties in the generator
        //
        Set<String> pathMutations = generator.generate(pathsToProcess)
        pathMutations.each { pathMutation ->
            urlMutations << new URL(targetURL.protocol, targetURL.host, targetURL.port, pathMutation)
        }

        urlMutations
    }

    private List<String> retrieveStaticEndpointOrContentPaths(URL targetUrl, List<String> contentUrls, List<String> paths) {
        boolean hasEndpointPaths = paths.size() > 0
        if (!hasEndpointPaths) {
            // the check has no paths which indicate a specific endpoint or servlet's
            // therefore it add content URL's instead for each mutations (target and targets.location)
            log.info("Probing content variants ${contentUrls.size()}")

            List<String> contentPaths = contentUrls.collect { url ->
                url.path
            }

            String rawPathOfTargetUrl = rawPathWithoutExtension(targetUrl)
            if (StringUtils.isNotEmpty(rawPathOfTargetUrl) && !contentPaths.contains(rawPathOfTargetUrl)) {
                contentPaths.add(0, rawPathOfTargetUrl)
            }

            return contentPaths
        }

        this.paths
    }


    private String rawPathWithoutExtension(URL url) {
        String path = url.getPath()
        int lastDotIndex = StringUtils.lastIndexOf(path, ".")

        if (lastDotIndex > 0) {
            return StringUtils.substring(path, 0, lastDotIndex)
        }

        path
    }

    private List<HttpRequestModel> prepareRequests(URL urlMutation, String queryString) {
        List<HttpRequestModel> preparedRequests = []

        // the first one will always be issues initially without any further authentication info
        preparedRequests << toHttpRequestModel(urlMutation, queryString)

        // now we build in authentication
        // first we try the headers sequentially, if there are any
        List<HttpHeader> authenticationHeaders = getAuthenticationHeaders()
        if (authenticationHeaders.size() > 0) {
            authenticationHeaders.eachWithIndex { authenticationHeader, i ->
                withHeader(authenticationHeader.getName(), authenticationHeader.getValue())
                preparedRequests << toHttpRequestModel(urlMutation, queryString)
            }
        }

        // now we try the cookies sequentially, if there are any
        // not implemented right now
        Map<String, String> authenticationCookies = getAuthenticationCookies()
        if (authenticationCookies.size() > 0) {
            authenticationCookies.eachWithIndex { authenticationCookie, i ->
                preparedRequests << toHttpRequestModel(urlMutation, queryString)
            }
        }

        preparedRequests
    }

    /**
     * Transforms an instance of this class into a {@link HttpRequestModel}
     * @param url Target URL
     * @param queryString Querystring
     * @return
     */
    HttpRequestModel toHttpRequestModel(url, queryString) {
        HttpRequestModel model = new HttpRequestModel(
                url: url,
                authenticationHeaders: authenticationHeaders,
                requestHeaders: requestHeaders,
                queryString: queryString,
                params: params,
                bodyType: bodyType,
                body: requestBody,
                bodyEncoding: bodyEncoding,
                cookies: authenticationCookies
        )

        model
    }

    /**
     * Add an additional header to the underlying requestDelegate
     * @param name
     * @param value
     * @return
     */
    void withHeader(String name, String value) {
        this.requestHeaders.put(name, value)
    }


    /* Getter and setter logic to easily setup the closure */

    def id(String id) {
        this.id = id
    }

    //getters and setters
    def name(String name) {
        this.name = name
    }

    // Handle paths
    void paths(String... path) {
        this.paths << path
    }

    void paths(List<String> paths) {
        this.paths.addAll(paths)
    }

    void paths(Closure closure) {
        def result = closure()
        if (result instanceof String) {
            this.paths << result
        } else if (isCollectionOrArray(result)) {
            this.paths.addAll(result)
        }
    }

    // Handle selectors
    void selectors(String... selector) {
        selectors << selector
    }

    void selectors(List<String> selectors) {
        this.selectors.addAll(selectors)
    }

    void selectors(Closure closure) {
        def result = closure()
        if (result instanceof String) {
            this.selectors << result
        } else {
            assert isCollectionOrArray(result)
            this.selectors.addAll(result)
        }
    }

    // Handle extensions
    void extensions(String... extension) {
        extensions << extension
    }

    void extensions(List<String> extensions) {
        this.extensions.addAll(extensions)
    }

    void extensions(Closure closure) {
        def result = closure()
        if (result instanceof String) {
            this.extensions << result
        } else {
            assert isCollectionOrArray(result)
            this.extensions.addAll(result)
        }
    }

    // Handle suffixes
    void suffixes(String... suffix) {
        this.suffixes << suffix
    }

    void suffixes(List<String> suffixes) {
        this.suffixes.addAll(suffixes)
    }

    void suffixes(Closure closure) {
        def result = closure()
        if (result instanceof String) {
            this.suffixes << result
        } else {
            assert isCollectionOrArray(result)
            this.suffixes.addAll(result)
        }
    }

    // Handle bypasses
    void bypasses(String... bypass) {
        bypasses << bypass
    }

    void bypasses(List<String> bypasses) {
        this.bypasses.addAll(bypasses)
    }

    void bypasses(Closure closure) {
        def result = closure()
        if (result instanceof String) {
            this.bypasses << result
        } else {
            assert isCollectionOrArray(result)
            this.bypasses.addAll(result)
        }
    }

    // handles querystrings
    void querystring(String... querystrings) {
        this.querystrings.addAll querystrings
    }

    void querystring(List<String> querystrings) {
        this.querystrings.addAll(querystrings)
    }

    void querystring(Closure closure) {
        def result = closure()
        if (result instanceof String) {
            this.querystrings << result
        } else if (isCollectionOrArray(result)) {
            this.querystrings.addAll(result)
        }
    }

    // parameter handling
    void param(String key, Object value) {
        this.params.put(key, value)
    }

    void parameters(Map<String, Object> parameters) {
        this.params.putAll(parameters)
    }

    /* Header configuration and request delegate post processing */

    void header(String key, Object value) {
        this.requestHeaders.put(key, value)
    }

    void headers(Map<String, Object> headers) {
        this.requestHeaders.putAll(headers)
    }

    void authenticationHeaders(Map<String, Object> headers) {
        headers.each { entry ->
            HttpHeader header = new HttpHeader(name: entry.key, value: entry.value)
            this.authenticationHeaders.add(header)
        }
    }

    void authenticationHeader(String name, String value) {
        HttpHeader header = new HttpHeader(name: name, value: value)
        this.authenticationHeaders.add(header)
    }

    void basicAuthentication(String user, String pass) {
        String credentials = "${user}:${pass}".bytes.encodeBase64().toString()
        HttpHeader header = new HttpHeader(name: "Authorization", value: "Basic ${credentials}")
        this.authenticationHeaders.add(header)
    }

    void basicAuthentication(Credential credential) {
        HttpHeader header = new HttpHeader(name: "Authorization", value: credential.toBasicAuth())
        this.authenticationHeaders.add(header)
    }

    void authenticationCookies(Map<String, Object> cookies) {
        this.authenticationCookies.putAll(cookies)
    }

    /* Detection rule configuration */

    // Handle the detector configurations
    def detect(Closure closure) {
        this.detectionRule = closure
    }

    def createDetectionRule(HttpRequestResponse requestResponse) {
        createDetectionRule(this.detectionRule, requestResponse)
    }

    def createDetectionRule(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = DetectionRule) Closure closure, HttpRequestResponse requestResponse) {
        DetectionRule rule = new DetectionRule(requestResponse)
        closure.setDelegate(rule)
        closure.setResolveStrategy(Closure.DELEGATE_FIRST)
        return closure
    }

    /* request handling through a request delegate closure */

    /**
     * Initializes the request and response method and set's a closure that does the actual request handling
     * @param method
     * @return
     */
    def method(String method) {
        this.method = method
    }

    /**
     * Set's the body for
     * @param closure
     * @return
     */
    def body(Closure closure) {
        this.requestBody = closure
    }

    def body(String bodyType, Closure closure) {
        this.requestBody = closure
        this.bodyType = bodyType
    }


    def bodyType(String bodyType) {
        this.bodyType = bodyType
    }

    def body(String bodyType, String bodyEncoding, Closure closure) {
        this.requestBody = closure
        this.bodyType = bodyType
        this.bodyEncoding = bodyEncoding
    }

    boolean isCollectionOrArray(object) {
        [Collection, Object[]].any { it.isAssignableFrom(object.getClass()) }
    }

    /**
     * Set wether this step should produce a reportable issue when the detection rule matches.
     * @param reportIssue
     */
    void reportable(boolean reportIssue) {
        this.reportable = reportIssue
    }

    /**
     * Disable that any reportable issue is reported with the parent check when the detection rule matches.
     * This can be necessary if the issue is supposed to be evaluated by a following step only.
     */
    void notReportable() {
        this.reportable = false
    }
}