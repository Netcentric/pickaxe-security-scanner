/*
 * (C) Copyright 2020 Netcentric AG.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.model

/**
 * Represents a scan issue detected by a check
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 03/2019
 */
class Issue {

    // this one has to be created on object creation
    String issueId = UUID.randomUUID().toString()

    URI url

    String checkId

    boolean shouldBeReported = true

    String name

    VulnerabilityDescription vulnerability

    List<String> requestMessages = []

    List<String> responseMessages = []

    List<String> reportedRequestFile = []

    List<String> reportedResponseFile = []

    String getIdentifier(){
        "$checkId-$issueId"
    }

    void vulnerability(VulnerabilityDescription vulnerability){
        this.vulnerability = vulnerability
    }

    void addMessage(HttpRequestResponse httpRequestResponse) {
        // not implemented yet. requires to go for a different http api to get raw request and response
    }

    void doNotReportIt(){
        this.shouldBeReported = false
    }

    @Override
    String toString() {
        return "Issue{" +
                "url=" + url +
                ", vulnerability=" + vulnerability +
                ", requestMessages=" + requestMessages +
                ", responseMessages=" + responseMessages +
                '}';
    }
}
