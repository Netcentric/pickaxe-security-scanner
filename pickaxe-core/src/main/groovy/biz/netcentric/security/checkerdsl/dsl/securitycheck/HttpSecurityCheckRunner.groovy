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
import biz.netcentric.security.checkerdsl.http.AsyncHttpClient
import biz.netcentric.security.checkerdsl.http.method.HttpRequestModel
import biz.netcentric.security.checkerdsl.model.HttpRequestResponse
import biz.netcentric.security.checkerdsl.model.Issue
import biz.netcentric.security.checkerdsl.model.ScanContext
import groovy.util.logging.Slf4j

/**
 * Executes an actual scan based on a HttpSecurityCheckStep. It consumes the HttpSecurityCheckStep's configuration and writes back the results.
 * It is not responsible for coordinating the actual order of executions nor any details.
 */
@Slf4j
class HttpSecurityCheckRunner {

    HttpSecurityCheckHistory httpSecurityCheckHistory = new HttpSecurityCheckHistory()

    ScanContext context

    AsyncHttpClient httpClient

    /**
     * Executes a single HttpSecurityCheckStep and returns a list of issues detected by the step's evaluation logic.
     * The list might be empty if nothing has been found.
     *
     * @param checkStep The HttpSecurityCheckStep
     * @return List of issues
     */
    List<Issue> execute(HttpSecurityCheckStep checkStep) {
        assert this.httpClient != null
        assert this.context != null

        // prepares the requests which are passed to the http client
        List<HttpRequestModel> preparedRequests = checkStep.preparedRequestModels(context.getUrl(), context.getContentUrls())

        // fire all requests
        List<HttpRequestResponse> requestResponses = sendRequests(preparedRequests)

        // now we evaluate all responses
        List<Issue> findingsOfThisStep = []
        requestResponses.each { requestResponse ->
            if (hasSuccessfullyDetectedPatterns(checkStep, requestResponse)) {
                Issue issue = createIssue(checkStep, requestResponse)
                findingsOfThisStep.add issue
                this.httpSecurityCheckHistory.add(checkStep, issue)
            }
        }

        findingsOfThisStep
    }

    private List<HttpRequestResponse> sendRequests(List<HttpRequestModel> preparedHttpRequests) {
        assert preparedHttpRequests != null && preparedHttpRequests.size() > 0

        List<HttpRequestResponse> results = []

        HttpRequestModel initialRequest = preparedHttpRequests.remove(0)
        Optional<HttpRequestResponse> initialRequestResponse = this.httpClient.execute(initialRequest)
        if(initialRequestResponse.isPresent()){
            results.add initialRequestResponse.get()

            if(preparedHttpRequests.size() > 0){
                results.addAll this.httpClient.execute(preparedHttpRequests)
            }
        }else{
            log.info("Initial request was not successful and did not provide a response. " +
                    "${initialRequest.getUrl().toString()} All subsequent requests for this check are stopped.")
        }

        results
    }

    /**
     * Looks into the HttpRequestResponse and checks wether the expected detection patterns apply.
     *
     * @param checkStep
     * @param requestResponse
     * @return
     */
    def hasSuccessfullyDetectedPatterns(HttpSecurityCheckStep checkStep, HttpRequestResponse requestResponse) {
        // composes the detection rule for the current HttpRequestResponse
        Closure<DetectionRule> ruleDelegate = checkStep.createDetectionRule(requestResponse)

        // execute the different check closures
        boolean result = ruleDelegate()

        // now we evaluate the results
        ruleDelegate.issuesDetected()
    }

    /**
     * Creates an Issue based on the HttpSecurityCheckStep's findings. It records the raw request and response.
     *
     * @param checkStep The HttpSecurityCheckStep
     * @param requestResponse HttpRequestResponse
     * @return Issue
     */
    def createIssue(HttpSecurityCheckStep checkStep, HttpRequestResponse requestResponse) {
        Issue issue = new Issue(url: requestResponse.getUri(), checkId: checkStep.getId())
        issue.requestMessages << requestResponse.rawRequest
        issue.responseMessages << requestResponse.trimmedResponse
        issue.setShouldBeReported(checkStep.isReportable())

        issue
    }

    /**
     * Provides all reportable findings.
     * @return List of Issues
     */
    List<Issue> getReportableFindings(){
        this.httpSecurityCheckHistory.getAllFindings(true)
    }
}