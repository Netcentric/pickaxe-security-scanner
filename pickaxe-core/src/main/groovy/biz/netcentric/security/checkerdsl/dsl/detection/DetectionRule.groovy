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

/**
 * Evaluates detection rule expectations for a security check.
 */
@Slf4j
class DetectionRule {

    HttpRequestResponse requestResponse

    def strictMode = true

    List<DetectionResult> allGroup = []

    List<DetectionResult> oneOfGroup = []

    DetectionRule(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse
    }

    def call(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = DetectionRule) Closure closure) {
        log.debug "call"
        closure.setDelegate(this)
        closure.setResolveStrategy(Closure.DELEGATE_FIRST)
        closure()
    }

    def all(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = DetectionRule) Closure closure) {
        log.debug("Stepping into all")
        ResponseChecker evaluator = new ResponseChecker(requestResponse)
        closure.setDelegate(evaluator)
        closure.setResolveStrategy(Closure.DELEGATE_FIRST)

        closure()

        allGroup.addAll(closure.results)
    }


    def oneOf(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = DetectionRule) Closure closure) {
        log.debug("Stepping into oneOf")
        ResponseChecker evaluator = new ResponseChecker(requestResponse)
        closure.setDelegate(evaluator)
        closure.setResolveStrategy(Closure.DELEGATE_FIRST)

        closure()

        oneOfGroup.addAll(closure.results)
    }

    void strict(boolean strict) {
        this.strictMode = strict
    }

    boolean issuesDetected() {
        // we are fine if it returns false
        boolean global = false

        if (allGroup.size() > 0) {
            int allGroupMatches = 0
            allGroup.each { detectionResult ->
                if (detectionResult.result) {
                    allGroupMatches++
                }
            }

            log.debug "All rule group has: ${allGroupMatches} matches"

            // do we have as many matches as entries as in the all group all closures have to createIssue result== true
            global = allGroupMatches == allGroup.size()
        }

        log.debug "All group closures found at least one match"

        if (oneOfGroup.size() > 0) {
            int oneOfGroupMatches = 0
            oneOfGroup.each { detectionResult ->
                if (detectionResult.result) {
                    oneOfGroupMatches++
                }
            }

            log.debug "OneOf rule group has: ${oneOfGroupMatches} matches"

            // if it is true already then we have a match ... one of
            if (strictMode) {
                global = global && oneOfGroupMatches > 0
            } else {
                global = global || oneOfGroupMatches > 0
            }
        }

        log.debug "DetectionRule for ${this.requestResponse.getUri().toString()} found a match: ${global}"

        global
    }
}

