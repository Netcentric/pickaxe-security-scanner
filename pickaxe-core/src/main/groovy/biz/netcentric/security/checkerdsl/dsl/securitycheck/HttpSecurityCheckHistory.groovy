/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.dsl.securitycheck

import biz.netcentric.security.checkerdsl.model.Issue
import groovy.util.logging.Slf4j

/**
 * History of a security check run. HistoryRecords are added to this class and stored internally.
 * The history is unique to each run and used at a later point in term to be evaluated by the report handling.
 */
@Slf4j
class HttpSecurityCheckHistory {

    LinkedHashMap<String, HistoryRecord> history = new LinkedHashMap()

    /**
     * Adds a list of issues.
     *
     * @param step The current HttpSecurityCheckStep
     * @param detectedIssues List of issues
     */
    void add(HttpSecurityCheckStep step, List<Issue> detectedIssues) {
        history.put(step.getId() + " - " + System.nanoTime(), new HistoryRecord(step: step, detectedIssues: detectedIssues))
    }

    /**
     * Adds a single issues.
     *
     * @param step The current HttpSecurityCheckStep
     * @param detectedIssue The detected issue
     */
    void add(HttpSecurityCheckStep step, Issue detectedIssue) {
        history.put(step.getId() + " - " + System.nanoTime(), new HistoryRecord(step: step, detectedIssues: [detectedIssue]))
    }

    /**
     * Provides all recorded.
     *
     * @param reportableOnly Filters if only reportable issues are returned
     * @return List of Issues
     */
    List<Issue> getAllFindings(boolean reportableOnly) {
        history.values().stream()
                .map { record -> record.getDetectedIssues() }
                .flatMap { issues -> issues.stream() }
                .filter { issue -> reportableOnly && !issue.isShouldBeReported() ? false : true }
                .toList()
    }
}