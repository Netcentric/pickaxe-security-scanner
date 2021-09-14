/*
 * (C) Copyright 2020 Netcentric AG.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.report.handlers

import biz.netcentric.security.checkerdsl.model.Issue
import biz.netcentric.security.checkerdsl.report.Format
import biz.netcentric.security.checkerdsl.report.ReportHandler
import biz.netcentric.security.checkerdsl.report.data.ScanResultReport
import groovy.util.logging.Slf4j

@Slf4j
class ConsoleLoggerOutputHandler implements ReportHandler {

    static final String NAME = "default-console"

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
        scanResultReport.getFindings().each {
            Issue issue = it
            log.info("Detected an issue " + System.lineSeparator() + issue.toString())
        }
    }

    @Override
    void postProcessingAction(ScanResultReport scanResultReport) {

    }
}
