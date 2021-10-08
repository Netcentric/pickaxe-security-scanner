/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.model

/**
 * Value object which reflects the result of a test execution.
 */
class CheckExecutionResult {

    String checkId

    String checkName

    VulnerabilityDescription vulnerabilityDescription

    List<Issue> issues

    /**
     * Does check execution result in any findings?
     *
     * @return true if number of issues is larger then zero
     */
    boolean hasFindings() {
        issues != null && issues.size() > 0
    }
}
