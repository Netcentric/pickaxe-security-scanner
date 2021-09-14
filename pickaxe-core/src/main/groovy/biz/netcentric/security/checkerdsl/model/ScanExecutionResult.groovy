/*
 * (C) Copyright 2020 Netcentric AG.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.model

class ScanExecutionResult {

    String target

    List<CheckExecutionResult> checkExecutionResults = []

    List<Issue> findings = []

    void addCheckResult(CheckExecutionResult checkExecutionResult){
        checkExecutionResults.add(checkExecutionResult)

        if (checkExecutionResult.hasFindings()) {
            findings.addAll(checkExecutionResult.getIssues())
        }
    }

    boolean hasFindings(){
        this.findings.size() > 0
    }
}
