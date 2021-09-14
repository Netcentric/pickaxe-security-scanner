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

import biz.netcentric.security.checkerdsl.model.Issue
import groovy.util.logging.Slf4j

/**
 * History of a security check run. HistoryRecords are added to this class and stored internally.
 */
@Slf4j
class HttpSecurityCheckHistory {

    LinkedHashMap<String, HistoryRecord> history = new LinkedHashMap()

    void add(HttpSecurityCheckStep step, List<Issue> detectedIssues) {
        history.put(step.getId() + " - " + System.nanoTime(), new HistoryRecord(step: step, detectedIssues: detectedIssues))
    }

    void add(HttpSecurityCheckStep step, Issue detectedIssue) {
        history.put(step.getId() + " - " + System.nanoTime(), new HistoryRecord(step: step, detectedIssues: [detectedIssue]))
    }

    List<Issue> getAllFindings(boolean reportableOnly) {
        history.values().stream()
                .map { record -> record.getDetectedIssues() }
                .flatMap { issues -> issues.stream() }
                .filter { issue -> reportableOnly && !issue.isShouldBeReported() ? false : true }
                .toList()
    }
}