/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.report.data

import java.util.stream.Collectors
import biz.netcentric.security.checkerdsl.model.Issue
import biz.netcentric.security.checkerdsl.model.ScanExecutionResult

/**
 * Value object which is used to nicely render the information relevant in a report
 */
class ScanResultReport {

    String target

    List<SecurityCheckReportEntity> executedChecks = []

    List<Issue> findings

    Map<String, List<Issue>> findingsMap;


    int numberOfFindings

    ScanResultReport(){}

    ScanResultReport(ScanExecutionResult scanExecutionResult){
        scanExecutionResult.getCheckExecutionResults().each {check ->
            SecurityCheckReportEntity reportEntity = new SecurityCheckReportEntity()

            reportEntity.setId(check.getCheckId())
            reportEntity.setName(check.getCheckName())
            reportEntity.setVulnerabilityName(check.getVulnerabilityDescription().getName() + " " + check.getCheckName())
            reportEntity.setVulnerabilityDescription(check.getVulnerabilityDescription().getDescription())
            reportEntity.setCve(check.getVulnerabilityDescription().getCve())
            reportEntity.setSuggestedMitigation(check.getVulnerabilityDescription().getRemediation())
            reportEntity.setNumberOfFindings check.getIssues().size()

            executedChecks.add reportEntity
        }

        this.findings = scanExecutionResult.getFindings()
        this.findingsMap = findings.groupBy { it.checkId }

        this.numberOfFindings = getFindings().size()
        this.target = scanExecutionResult.getTarget()
    }
}
