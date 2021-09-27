/*
 *
 *  * (C) Copyright 2020 Netcentric AG.
 *  *
 *  * All rights reserved. This program and the accompanying materials
 *  * are made available under the terms of the Eclipse Public License v1.0
 *  * which accompanies this distribution, and is available at
 *  * http://www.eclipse.org/legal/epl-v10.html
 *
 */
package biz.netcentric.security.checkerdsl.dsl

import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.http.AsyncHttpClient
import biz.netcentric.security.checkerdsl.http.HttpClientConfig
import biz.netcentric.security.checkerdsl.model.CheckExecutionResult
import biz.netcentric.security.checkerdsl.model.ScanContext
import biz.netcentric.security.checkerdsl.model.ScanExecutionResult
import biz.netcentric.security.checkerdsl.report.Reporter
import groovy.util.logging.Slf4j

/**
 * Defines a scan and allow to register targets, configs and HttpSecurityChecks.
 * Requires a {@link SecurityCheckProvider} to manage them.
 * Requires a {@link ScanContext}, {@link ScanConfiguration and a Reporter configuration
 */
@Slf4j
class ScanDelegate {

    ScanContext targetContextDelegate

    ScanConfiguration configDelegate

    SecurityCheckProvider securityCheckProviderDelegate

    Reporter reporterDelegate

    List<HttpSecurityCheck> checks = []

    /* Call methods of this closure delegate which trigger the actual execution of the closure */

    /**
     * Calls the closure
     * @return
     */
    def call() {
        execute(targetContextDelegate)
    }

    /**
     * Calls the closure with a single target
     *
     * @param url
     * @return
     */
    def call(String url) {
        def context = new ScanContext(url)
        execute(context)
    }


    /**
     * Calls the closure with a ScanContext
     *
     * @param ScanContext
     * @return
     */
    def call(ScanContext context) {
        execute(context)
    }

    /* Target definition */

    def target(String url) {
        this.targetContextDelegate = new ScanContext(url)
    }

    def target(URL url) {
        this.targetContextDelegate = new ScanContext(url)
    }

    def target(String url, List<String> contentTargets) {
        this.targetContextDelegate = new ScanContext(url, contentTargets)
    }

    def target(Closure<ScanContext> target) {
        this.targetContextDelegate = target
    }

    def config(Closure<ScanConfiguration> config) {
        this.configDelegate = ScanConfiguration.create config
    }

    /* Load security checks in the context of this delegate */

    def register(Closure<HttpSecurityCheck> closure) {
        HttpSecurityCheck httpSecurityCheck = HttpSecurityCheck.create { closure }
        if (this.securityCheckProviderDelegate == null) {
            throw new RuntimeException("SecurityCheckProvider has to be set up initially")
        }
        this.securityCheckProviderDelegate.add(httpSecurityCheck)
    }

    def register(HttpSecurityCheck httpSecurityCheck) {
        if (this.securityCheckProviderDelegate == null) {
            throw new RuntimeException("SecurityCheckProvider has to be set up initially")
        }

        this.securityCheckProviderDelegate.add(httpSecurityCheck)
    }

    def register(List<String> scriptLocations) {
        if (this.securityCheckProviderDelegate == null) {
            throw new RuntimeException("SecurityCheckProvider has to be set up initially")
        }

        scriptLocations.each { scriptLocation ->
            // catches location based loading in case of an error to make it more resilient.
            // As with multiple locations it might be more likely to fail from time to time
            try {
                this.securityCheckProviderDelegate.initializeCheckFromFileSystem(scriptLocation)
            } catch (Exception ex) {
                log.error("Unable to load script from: " + scriptLocation, ex)
            }
        }
    }


    /**
     * Loads one or multiple script from the defined locations.
     * This can be either a a single script, a list of single scripts, a single directory or even a list of directories.
     * Must be called before the actual scan execution as the scripts need to be loaded and initialized before.
     *
     * All load scripts must be valid {@link HttpSecurityCheck}s
     *
     * @param scriptLocations Array of file or folders paths
     * @return
     */
    def register(String... scriptLocations) {
        this.register(Arrays.asList(scriptLocations))
    }

    /**
     * Defines the reporter which encapsulates the reporting strategy.
     * @param config
     * @return
     */
    def reporter(Closure<Reporter> config) {
        this.reporterDelegate = Reporter.create config
    }


    List<CheckExecutionResult> execute(ScanContext scanContext) {
        assert securityCheckProviderDelegate != null

        // we add this in addition to the constructor to make sure everything is running as expected
        scanContext.initialize()

        List<HttpSecurityCheck> allChecks = []

        if (this.configDelegate.getNames()) {
            allChecks.addAll securityCheckProviderDelegate.getByName(this.configDelegate.getNames())
        } else if (this.configDelegate.getCategories()) {
            allChecks.addAll securityCheckProviderDelegate.getByCategory(this.configDelegate.getCategories())
        } else {
            allChecks.addAll securityCheckProviderDelegate.getAllChecks()
        }

        List<String> ignoredChecks = this.configDelegate.getIgnored()
        List<String> falsePositives = this.configDelegate.getFalsePositives()

        List<HttpSecurityCheck> filteredChecks = allChecks.stream()
                .filter { check -> !ignoredChecks.contains(check.getId())}
                .map {check ->
                    if(falsePositives.contains(check.getId())){
                        check.setPotentialFalsePositive(true)
                    }
                    return check
                }
                .toList()

        if(ignoredChecks.size() > 0){
            log.info("Ignoring the following checks: " + ignoredChecks.join(", "))
        }

        // opening the shared http client for the scan
        HttpClientConfig httpClientConfig = this.configDelegate.createHttpClientConfig()
        AsyncHttpClient httpClient = new AsyncHttpClient(httpClientConfig)

        List<CheckExecutionResult> checkResults = new ArrayList<>()

        ScanExecutionResult scanExecutionResult = new ScanExecutionResult()
        scanExecutionResult.setTarget(scanContext.getUrl().toString())

        // execute it sequentially right now to avoid problems coming with a high number of concurrent requests
        // - avoid blacklisting on WAF and CDN level
        // - avoid trashing the target server. we do not want to break it
        // adding an option for sharding it to multiple clients or threads is an option for the future but not required at the moment
        long throttlingTimeout = this.configDelegate.getCheckThrottlingMillis()
        int numberOfChecks = filteredChecks.size()

        filteredChecks.eachWithIndex {check, i ->
            CheckExecutionResult result = check(httpClient, scanContext)
            scanExecutionResult.addCheckResult(result)

            if(throttlingTimeout > 0 && i < numberOfChecks - 1){
                log.info("Pausing execution of next check for {} to throttle and avoid blocking.", throttlingTimeout)
                Thread.sleep(throttlingTimeout)
            }
            log.info "------------------ "
        }

        def numberOfFindings = scanExecutionResult.getFindings().size()
        log.info "Check execution completed. Executed {} checks and detected {} findings.", numberOfChecks, numberOfFindings
        if(numberOfFindings > 0) {
            log.info "Please check the report for details."
        }

        // Shutdown http client config internally
        httpClient.shutdown()

        log.info "------------------"

        // createIssue only if a createIssue delegate has been configured
        if (reporterDelegate != null) {
            reporterDelegate.generate(scanExecutionResult)
        }

        // we return that list anyway. maybe a consumer wants to do something else with it.
        checkResults
    }

    @Override
    String toString() {
        return "ScanDelegate{" +
                "targetContextDelegate=" + targetContextDelegate +
                ", configDelegate=" + configDelegate +
                ", securityCheckProviderDelegate=" + securityCheckProviderDelegate +
                ", reporterDelegate=" + reporterDelegate +
                ", checks=" + checks +
                '}';
    }
}


class Scan {

    /**
     * Creates the {@link ScanDelegate} and initializes a SecurityCheckProvider without any additional customization options
     * @param scanClosure
     * @return ScanDelegate
     */
    static ScanDelegate create(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = ScanDelegate) Closure scanClosure) {
        SecurityCheckProvider securityCheckProvider = new SecurityCheckProvider()
        initializeScan(securityCheckProvider, scanClosure)
    }

    /**
     * Creates the {@link ScanDelegate} but expects a SecurityCheckProvider which can be customized before.
     * @param scanClosure
     * @return ScanDelegate
     */
    static ScanDelegate create(SecurityCheckProvider securityCheckProvider, @DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = ScanDelegate) Closure scanClosure) {
        initializeScan(securityCheckProvider, scanClosure)
    }

    /**
     * Does the actually heavy lifting of setting up the  {@link ScanDelegate} and the respective resolveStrategy
     * @param scanClosure
     * @return ScanDelegate
     */
    private static ScanDelegate initializeScan(SecurityCheckProvider securityCheckProvider, Closure scanClosure) {
        ScanDelegate scanSpec = new ScanDelegate(securityCheckProviderDelegate: securityCheckProvider)
        scanClosure.setDelegate(scanSpec)
        scanClosure.resolveStrategy = Closure.DELEGATE_FIRST
        scanClosure()

        scanSpec
    }
}