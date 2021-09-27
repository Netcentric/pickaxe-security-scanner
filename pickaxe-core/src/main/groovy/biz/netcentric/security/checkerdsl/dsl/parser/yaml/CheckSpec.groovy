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

package biz.netcentric.security.checkerdsl.dsl.parser.yaml

import biz.netcentric.security.checkerdsl.model.Severity

class CheckSpec {

    String name

    String id

    Vulnerability vulnerability

    List<Step> steps

    List<String> categories

    @Override
    String toString() {
        return "CheckSpec{" +
                "id='" + id + '\'' +
                ", vulnerability=" + vulnerability +
                ", steps=" + steps +
                ", categories=" + categories +
                '}';
    }
}

class Vulnerability {

    String name

    String description

    String remediation

    String cve

    String severity

    Closure toClosure(){

        return {
            name owner.name

            description owner.description

            remediation owner.remediation

            cve([owner.cve])

            severity Severity.valueOf(owner.severity)
        }
    }

    @Override
    String toString() {
        return "Vulnerability{" +
                "name='" + name + '\'' +
                ", description='" + description + '\'' +
                ", remediation='" + remediation + '\'' +
                ", cve='" + cve + '\'' +
                ", severity='" + severity + '\'' +
                '}';
    }
}

class Step {

    String name

    String method

    List<String> paths = []

    List<String> extensions = []

    List<Rule> detect = []

    List<String> querystrings = []

    Map<String, String> requestHeaders = [:]

    Map<String, String> authenticationHeaders = [:]

    Map<String, String> authenticationCookies = [:]

    Map<String, String> params = [:]

    Closure toSecurityCheckClosure() {
        def detectionClosure = {}
        this.detect.each { rule ->
            detectionClosure = detectionClosure << rule.toClosure()
        }

        return {
            id owner.name
            name owner.name
            method owner.method
            paths owner.paths
            extensions owner.extensions
            parameters owner.params
            querystring owner.querystrings
            authenticationHeaders owner.authenticationHeaders
            authenticationCookies owner.authenticationCookies
            headers owner.requestHeaders
            detect detectionClosure
        }
    }

    @Override
    String toString() {
        return "Step{" +
                "name='" + name + '\'' +
                ", method='" + method + '\'' +
                ", paths=" + paths +
                ", extensions=" + extensions +
                ", detect=" + detect +
                ", querystrings=" + querystrings +
                ", requestHeaders=" + requestHeaders +
                ", authenticationHeaders=" + authenticationHeaders +
                ", params=" + params +
                '}';
    }
}

class Rule {

    String type

    int expectedStatusCode

    List bodyContains

    Closure toClosure() {
        String[] bodySearchTokens = bodyContains as String[]

        def ruleContent = {
            checkStatusCode owner.expectedStatusCode
            bodyContains bodySearchTokens
        }

        // the actual ruletype determines if it is an all conditions must match rule or a one condition must match rule
        if (type == "all") {
            return {
                all ruleContent
            }
        }else {
            return {
                oneOf ruleContent
            }
        }
    }

    @Override
    String toString() {
        return "Rule{" +
                "type='" + type + '\'' +
                ", expectedStatusCode=" + expectedStatusCode +
                ", bodyContains=" + bodyContains +
                '}';
    }
}
