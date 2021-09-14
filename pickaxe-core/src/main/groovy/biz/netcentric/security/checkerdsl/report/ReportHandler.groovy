/*
 * (C) Copyright 2020 Netcentric AG.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.report


import biz.netcentric.security.checkerdsl.report.data.ScanResultReport

/**
 * Handles a list of issues and transforms them to a createIssue.
 */
interface ReportHandler {

    /**
     * Name of the handler
     *
     * @return String
     */
    String getName()

    /**
     * Provides the output format
     *
     * @return Format descriptor of the report
     */
    Format getOutputFormat()

    /**
     * Set's the output file or null if not available.
     */
    void setOutputLocation(File file)

    /**
     * Provides the output file or null if not available.
     *
     * @return File or null
     */
    File getOutputFile()

    /**
     * Writes a report based on the ScanExecutionResult
     *
     * @param reportName Name of the report
     * @param scanResultReport Execution result of a scan
     */
    void writeReport(String reportName, ScanResultReport scanResultReport)

    /**
     * Executes the report handlers post processing actions which can be for instance cleanup tasks
     *
     * @param scanResultReport Execution result of a scan
     */
    void postProcessingAction(ScanResultReport scanResultReport)
}