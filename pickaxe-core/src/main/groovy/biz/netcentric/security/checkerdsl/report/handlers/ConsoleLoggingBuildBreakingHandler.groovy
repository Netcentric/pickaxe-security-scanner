/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.report.handlers

import biz.netcentric.security.checkerdsl.exception.IssuesDetectedException
import biz.netcentric.security.checkerdsl.report.Format
import biz.netcentric.security.checkerdsl.report.ReportHandler
import biz.netcentric.security.checkerdsl.report.data.ScanResultReport
import biz.netcentric.security.checkerdsl.report.data.SecurityCheckReportEntity
import groovy.util.logging.Slf4j

@Slf4j
class ConsoleLoggingBuildBreakingHandler implements ReportHandler {

    static final String NAME = "console-log-build-breaker"

    @Override
    String getName() {
        return NAME
    }

    @Override
    Format getOutputFormat() {
        return Format.JSON
    }

    @Override
    void setOutputLocation(File file) {
        // not implemented as it is not required
    }

    @Override
    File getOutputFile() {
        return null
    }

    @Override
    void writeReport(String reportName, ScanResultReport scanResultReport) {
        scanResultReport.getExecutedChecks().each {
            SecurityCheckReportEntity result = it
            log.info("Executed check: " + System.lineSeparator() + result.toExtendedName())
            int numberOfFindings = result.getNumberOfFindings()
            log.info("Findings: $numberOfFindings")
        }

        def numberOfChecks = scanResultReport.getExecutedChecks().size()
        log.info("Total Number of Checks: $numberOfChecks")

        def totalFindings = scanResultReport.getNumberOfFindings()
        log.info("Total Findings: $totalFindings")
    }

    @Override
    void postProcessingAction(ScanResultReport scanResultReport) {
        if (scanResultReport.getFindings().size() > 0) {
            def numberOfIssues = scanResultReport.getFindings().size()
            throw new IssuesDetectedException("The scan detected the following number of issues in total: [$numberOfIssues]. Please check the report output.")
        }
    }
}