/*
 * (C) Copyright 2020 Netcentric AG.
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
import groovy.json.JsonGenerator
import groovy.json.JsonOutput
import groovy.util.logging.Slf4j

@Slf4j
class PrettyPrintJsonOutputHandler implements ReportHandler{

    static final String NAME = "json-pretty"

    static final String FORMAT = "%s.json"

    File outputFolder

    File outputFile

    @Override
    void setOutputLocation(File file) {
        if (file.isDirectory()) {
            outputFolder = file
        } else {
            throw new RuntimeException("File " + file.path + " is not a folder.")
        }
    }

    @Override
    String getName() {
        return NAME
    }

    @Override
    Format getOutputFormat() {
        return Format.JSON
    }


    @Override
    File getOutputFile(){
       outputFile
    }

    @Override
    void writeReport(String reportName, ScanResultReport scanResultReport) {

        if(outputFolder != null && outputFolder.exists() && outputFolder.isDirectory()){
            final FileTreeBuilder treeBuilder = new FileTreeBuilder(outputFolder)
            String fileName = String.format(FORMAT, reportName)

            JsonGenerator generator = new JsonGenerator.Options()
                    .excludeNulls()
                    .build()

            def output = generator.toJson(scanResultReport)
            def prettyPrintedJson = JsonOutput.prettyPrint(output)
            this.outputFile = treeBuilder.file(fileName, prettyPrintedJson)
        }
    }

    @Override
    void postProcessingAction(ScanResultReport scanResultReport) {
        // nothing to do here
    }
}
