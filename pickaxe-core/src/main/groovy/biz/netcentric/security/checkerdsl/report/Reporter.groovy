/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.report


import biz.netcentric.security.checkerdsl.model.ScanExecutionResult
import biz.netcentric.security.checkerdsl.report.data.ScanResultReport
import biz.netcentric.security.checkerdsl.report.handlers.*
import groovy.util.logging.Slf4j

@Slf4j
class Reporter {

    static final String NAME_PREFIX = "scan-results%s"

    List<String> selectedReporterHandlers = []

    Map<String, ReportHandler> availableHandlers = [:]

    Closure defaultConfiguration

    File outputFolder

    boolean withIndexPage = true

    /**
     * Adds the default configuration which is supposed to be used as a fallback to get out a config object for a respective handler
     *
     * @param configClosure
     */
    void config(Closure configClosure) {
        defaultConfiguration = configClosure
    }

    void setOutputLocation(File file) {
        if (file != null && !file.exists()) {
            file.mkdir()
        }

        if (file.isDirectory()) {
            this.outputFolder = file
        } else {
            throw new RuntimeException("File " + file.path + " is not a folder.")
        }
    }

    void setOutputLocation(String path) {
        File file = new File(path)
        setOutputLocation(file)
    }


    /**
     * Adds the key of a ReportHandler to the list of selected handlers
     *
     * @param reporterName
     */
    void register(Closure<String> reporterName) {
        selectedReporterHandlers.add reporterName()
    }

    /**
     * Registers a list of reporterNames
     * @param reporterNames String names
     *
     */
    void register(String... reporterNames) {
        selectedReporterHandlers.addAll(Arrays.asList(reporterNames))
    }

    /**
     * Registers a list of reporterNames
     * @param reporterNames String names
     *
     */
    void register(List<String> reporterNames) {
        selectedReporterHandlers.addAll(reporterNames)
    }

    /**
     * Adds a createIssue handler to the map of available reports and to the list of selected ones
     * @param closure
     */
    void handler(Closure<ReportHandler> closure) {
        ReportHandler reportHandler = closure()
        String key = reportHandler.getName()
        availableHandlers.put(key, reportHandler)
        selectedReporterHandlers.add(key)
    }

    protected add(ReportHandler reportHandler) {
        String key = reportHandler.getName()
        availableHandlers.put(key, reportHandler)
    }

    /**
     * Generate the reports by using the configured selected ReportHandlers
     * @param CheckExecutionResult containing a list of Issues
     */
    void generate(ScanExecutionResult scanExecutionResult) {
        this.generate(scanExecutionResult, this.defaultConfiguration)
    }

    /**
     * Generate the reports by using the configured selected ReportHandlers
     *
     * @param CheckExecutionResult containing a list of Issues
     * @parem defaultConfigClosure Configuration override
     */
    void generate(ScanExecutionResult scanExecutionResult, Closure defaultConfigClosure) {
        if (defaultConfigClosure != null) {
            defaultConfigClosure.delegate = this
            defaultConfigClosure()
        }

        ScanResultReport scanResultReport = new ScanResultReport(scanExecutionResult)

        String folderName = String.format(NAME_PREFIX, System.currentTimeSeconds())
        String fileName = String.format(NAME_PREFIX, "")

        final FileTreeBuilder treeBuilder = new FileTreeBuilder(this.outputFolder)
        File workingDirectory = treeBuilder.dir(folderName)

        // generates mandatory information such raw request and response messages
        applyRequestResponseReporter workingDirectory, fileName, scanResultReport

        // generates the scan reports
        List<File> outputFiles = []
        try {
            runSelectedReportHandlers outputFiles, workingDirectory, fileName, scanResultReport
        } finally {
            // needs to be in a finally block as some report handlers might throw an exception deliberately
            createIndexPage outputFiles, this.outputFolder
        }
    }

    private void runSelectedReportHandlers(List<File> outputFiles, File workingDirectory, String fileName, ScanResultReport scanResultReport) {
        log.info "Executing the following report handlers " + selectedReporterHandlers.join(",")

        selectedReporterHandlers.each {
            String reportHandlerName = it
            ReportHandler reportHandler = getMatchingOrFirstAlternative(reportHandlerName)
            if (reportHandler != null) {
                log.info("Executing report handler ${reportHandlerName}")

                reportHandler.setOutputLocation workingDirectory
                reportHandler.writeReport fileName, scanResultReport
                reportHandler.postProcessingAction scanResultReport

                log.info("Successfully reported with ${reportHandlerName}")
                outputFiles << reportHandler.getOutputFile()

            } else {
                log.error("Unable to find configured reporterDelegate [{}] or any starting with this name.", reportHandlerName)
            }
        }
    }

    private ReportHandler getMatchingOrFirstAlternative(String reportHandlerName) {
        ReportHandler reportHandler = availableHandlers.get(reportHandlerName)
        if(reportHandler == null){
            availableHandlers.each {availableHandler ->
                reportHandler = availableHandler.getKey().startsWith(reportHandlerName)
                if(reportHandler != null){
                    return reportHandler
                }
            }
        }
        return reportHandler
    }

    private void createIndexPage(List<File> outputFiles, File outputDirectory) {
        if (withIndexPage) {
            // writes an index page into the output location pointing to the latest reports
            // the index page should be linked by the html publisher in jenkins
            IndexPage indexFile = new IndexPage(outputFiles)
            indexFile.write outputDirectory

            log.debug "Index page created at $outputDirectory"
        } else {
            log.debug "Index page creation is disabled"
        }
    }

    private void applyRequestResponseReporter(File workingDirectory, String fileName, ScanResultReport scanResultReport) {
        ReportHandler requestAndResponseReporter = new RequestAndResponseReporter()
        requestAndResponseReporter.setOutputLocation(workingDirectory)
        requestAndResponseReporter.writeReport fileName, scanResultReport
        requestAndResponseReporter.postProcessingAction scanResultReport
    }

    static Reporter create(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = Reporter) Closure closure) {
        Reporter reporter = new Reporter()
        provideReportHandlers().each {
            reporter.add it
        }
        closure.setDelegate(reporter)
        closure.resolveStrategy = Closure.DELEGATE_FIRST
        closure()

        reporter
    }

    static List<ReportHandler> provideReportHandlers() {
        def handlers = []
        handlers.add new ConsoleLoggerOutputHandler()
        handlers.add new PrettyPrintJsonOutputHandler()
        handlers.add new HtmlTableOutputHandler()
        handlers.add new ConsoleLoggingBuildBreakingHandler()

        handlers
    }
}
