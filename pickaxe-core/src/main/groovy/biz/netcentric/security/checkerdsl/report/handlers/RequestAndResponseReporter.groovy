/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.report.handlers


import biz.netcentric.security.checkerdsl.report.Format
import biz.netcentric.security.checkerdsl.report.ReportHandler
import biz.netcentric.security.checkerdsl.report.data.ScanResultReport

class RequestAndResponseReporter implements ReportHandler {

    static final String MESSAGE_FOLDER_NAME = "messages"

    static final String NAME = "request-response"

    static final String FORMAT = "%s.json"

    File outputFolder

    File outputFile

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
        if (file.isDirectory()) {
            outputFolder = file
        } else {
            throw new RuntimeException("File " + file.path + " is not a folder.")
        }
    }

    @Override
    File getOutputFile() {
        outputFile
    }

    @Override
    void writeReport(String reportName, ScanResultReport scanResultReport) {
        if (outputFolder != null && outputFolder.exists() && outputFolder.isDirectory()) {
            final FileTreeBuilder treeBuilder = new FileTreeBuilder(outputFolder)
            treeBuilder.dir(MESSAGE_FOLDER_NAME) {
                scanResultReport.getFindings().each { issue ->
                    String securityCheckIdentifier = issue.getIdentifier()

                    // create a directory for the check-ID
                    // then write a message file for each request and response pair
                    treeBuilder.dir(securityCheckIdentifier) {
                        issue.requestMessages.eachWithIndex { message, i ->
                            File file = treeBuilder.file("request-" + i + ".txt", message)
                            issue.reportedRequestFile << file.getPath().replaceAll(outputFolder.absolutePath + "/", "")
                        }

                        issue.responseMessages.eachWithIndex { message, i ->
                            File file = treeBuilder.file("response-" + i + ".txt", message)
                            issue.reportedResponseFile << file.getPath().replaceAll(outputFolder.absolutePath + "/", "")
                        }
                    }
                }
            }
        }
    }

    @Override
    void postProcessingAction(ScanResultReport scanResultReport) {
        // nothing to do here
    }
}
