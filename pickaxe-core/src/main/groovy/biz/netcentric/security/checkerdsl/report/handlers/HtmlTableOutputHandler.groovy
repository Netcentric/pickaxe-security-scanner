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
import groovy.text.Template
import groovy.text.markup.MarkupTemplateEngine
import groovy.text.markup.TemplateConfiguration

class HtmlTableOutputHandler implements ReportHandler {

    static final String NAME = "html-table"

    static final String FORMAT = "%s.html"

    File outputFolder

    File outputFile

    @Override
    String getName() {
        return NAME
    }

    @Override
    Format getOutputFormat() {
        return Format.HTML
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
            String fileName = String.format(FORMAT, reportName)
            String output = createHtmlMarkup(fileName, scanResultReport)

            this.outputFile = treeBuilder.file(fileName, output)
        }
    }

    String createHtmlMarkup(String reportName, ScanResultReport scanResultReport){
        HashMap<String, Object> model = createModel(reportName, scanResultReport)
        Template template = createTemplate()

        def writer = new StringWriter()  // html is written here by markup builder
        Writable output = template.make(model)
        output.writeTo(writer)

        writer
    }

    private HashMap<String, Object> createModel(String reportName, ScanResultReport scanResultReport) {
        Map<String, Object> model = new HashMap<String, Object>()
        model.put "reportName", "Netcentric Pickaxe ::: Security Check Report ::: - $reportName"
        model.put "target", scanResultReport.getTarget()
        model.put "checks", scanResultReport.getExecutedChecks()
        model.put "numberOfChecks", scanResultReport.getExecutedChecks().size()
        model.put "numberOfFindings", scanResultReport.getNumberOfFindings()
        model.put "findings", scanResultReport.getFindings()
        model.put "findingsMap", scanResultReport.getFindingsMap()
        model.put "pathPrefix", this.outputFolder.absolutePath + "/"
        model
    }

    private Template createTemplate() {
        TemplateConfiguration config = new TemplateConfiguration()
        config.autoIndent = true
        config.autoNewLine = true

        MarkupTemplateEngine engine = new MarkupTemplateEngine(config)
        URL templateFile = getClass().getClassLoader().getResource("templates/base-html-layout.templ")

        engine.createTemplate(templateFile)
    }

    @Override
    void postProcessingAction(ScanResultReport scanResultReport) {
    }
}