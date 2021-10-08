/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.dsl.securitycheck

import biz.netcentric.security.checkerdsl.http.AsyncHttpClient
import biz.netcentric.security.checkerdsl.model.CheckExecutionResult
import biz.netcentric.security.checkerdsl.model.Issue
import biz.netcentric.security.checkerdsl.model.ScanContext
import biz.netcentric.security.checkerdsl.model.VulnerabilityDescription
import groovy.util.logging.Slf4j

/**
 * Coordinates and executes a security check against a target.
 * Delegates configuration and execution internally.
 * Each check execution must happen sequentially.
 * This class supports single as well as multistep checks.
 *
 * MultiStep checks require the previous step to be successful and provide at least 1 issue.
 * If STEP 1 provides results then the check will continue with STEP 2.
 * If not then it will log a message and stop further check execution.
 *
 * It relies on sequential execution of steps.
 * Individual steps are not executed in parallel, even though lower level requests within the steps might be.
 * The reason for keeping parallel execution available only on lower level is that there might be interdependencies where STEP 2 is only fired when STEP 1 was successful.
 */
@Slf4j
class HttpSecurityCheck {

    String id

    String name

    boolean potentialFalsePositive = false

    HttpSecurityCheckRunner httpSecurityCheckRunnerDelegate

    Closure<VulnerabilityDescription> vulnerabilityDescription

    List<String> categories = []

    List<HttpSecurityCheckStep> steps = []

    /**
     * Creates the HttpSecurityCheck based on a closure definition
     *
     * @param closure Closure which configures and instance of this class.
     *
     * @return HttpSecurityCheck
     */
    static HttpSecurityCheck create(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = HttpSecurityCheck) Closure closure) {
        assert closure != null
        HttpSecurityCheck httpSecurityCheck = new HttpSecurityCheck()
        closure.setDelegate(httpSecurityCheck)
        closure.setResolveStrategy(Closure.OWNER_FIRST)

        closure()

        httpSecurityCheck
    }

    /**
     * Creates the HttpSecurityCheck based on a an id, VulnerabilityDescription closure and a HttpSecurityCheck closure
     *
     * @param id ID of the check
     * @param vulnerabilityDescription The VulnerabilityDescription closure
     * @param checkSteps Single step.
     * @return HttpSecurityCheck
     */
    static HttpSecurityCheck create(String id, Closure description, Closure check) {
        HttpSecurityCheckStep step = HttpSecurityCheckStep.create(check)
        HttpSecurityCheck securityCheckSpec = new HttpSecurityCheck(id: id)
        securityCheckSpec.details(description)
        securityCheckSpec.addStep(step)
        securityCheckSpec
    }

    /**
     * Creates the HttpSecurityCheck based on a an id, VulnerabilityDescription closure and list of HttpSecurityCheckStep closures
     *
     * @param id ID of the check
     * @param vulnerabilityDescription The VulnerabilityDescription closure
     * @param checkSteps List of check steps. There must be a least one, else the check is never executed.
     * @return HttpSecurityCheck
     */
    static HttpSecurityCheck create(String id, Closure description, List<Closure> checkSteps) {
        HttpSecurityCheck securityCheckSpec = new HttpSecurityCheck(id: id)
        securityCheckSpec.details { description }

        checkSteps.each { checkStep ->
            HttpSecurityCheckStep step = HttpSecurityCheckStep.create(checkStep)
            securityCheckSpec.addStep(step)
        }
        securityCheckSpec
    }

    /**
     * Create a new HttpSecurityCheck with and id and a description and adds a list of {@link HttpSecurityCheckStep}s.
     *
     * @param id ID of the check
     * @param vulnerabilityDescription The VulnerabilityDescription closure
     * @param checkSteps List of check steps. There must be a least one, else the check is never executed.
     * @return HttpSecurityCheck
     */
    static HttpSecurityCheck createSecurityCheckWithSteps(String id, Closure description, List<HttpSecurityCheckStep> checkSteps) {
        HttpSecurityCheck securityCheckSpec = new HttpSecurityCheck(id: id)
        securityCheckSpec.details description
        checkSteps.each { check ->
            securityCheckSpec.addStep(check)
        }
        securityCheckSpec
    }

    /**
     * Triggers the actual execution of the closure and manages the execution of security check steps.
     *
     * @param httpclient HttpClient used to send requests
     * @param context ScanContext which provides information about the scan itself
     * @return CheckExecution value object
     */
    def call(AsyncHttpClient httpclient, ScanContext context) {
        // prepares the actual test runner initially and add the context to this execution
        this.httpSecurityCheckRunnerDelegate = initializeRunnerDelegate(httpclient, context)

        log.info("HttpSecurityCheck [ID: ${this.id} Name: ${this.name}] running now.")

        // using for a for loop with separate index here as each closures can not be exited without throwing an exception.
        int stepIndex = 1
        List<Issue> findingsOfLastStep = null
        for(check in steps){
            if(stepIndex > 1 && findingsOfLastStep.isEmpty()){
                log.info("Previous step did not provide any findings at index ${stepIndex}. Further execution of follow up steps is stopped now.")
                break
            }
            findingsOfLastStep = httpSecurityCheckRunnerDelegate.execute(check)
            log.info("Executing step ${stepIndex} resulted in ${findingsOfLastStep.size()} findings.")
            stepIndex++
        }

        VulnerabilityDescription vulnerability = VulnerabilityDescription.create this.vulnerabilityDescription

        List<Issue> findings = httpSecurityCheckRunnerDelegate.getReportableFindings().stream()
                .map { finding ->
                    finding.setCheckId(this.id)
                    finding.setName(this.name)
                    // the initially set vulnerability on a step has precedence. if it is not defined then we report the check wide
                    if(finding.getVulnerability() == null){
                        finding.setVulnerability(vulnerability)
                    }
                    finding
                }.toList()

        // send back a value object which allows us to report which checks
        // have been executed and which vulnerabilities have been evaluated
        log.info("HttpSecurityCheck ID: ${this.id} is completed.")
        return new CheckExecutionResult([checkId: this.id, checkName: this.name, vulnerabilityDescription: vulnerability, issues: findings])
    }

    /**
     * Creates and initializes a new {@link HttpSecurityCheckRunner}.
     *
     * @param preConfiguredHttpClient The http client to use.
     * @param context The Scan context containing target information.
     * @return HttpSecurityCheckRunner
     */
    def initializeRunnerDelegate(AsyncHttpClient preConfiguredHttpClient, ScanContext context) {
        new HttpSecurityCheckRunner([httpClient: preConfiguredHttpClient, context: context])
    }

    def vulnerability(Closure closure) {
        details(closure)
    }

    def id(String id) {
        this.id = id
    }

    def name(String name) {
        this.name = name
    }

    def identifier(String id) {
        this.id = id
    }

    /**
     * Creates the vulnerability description
     * @param closure
     * @return
     */
    def details(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = VulnerabilityDescription) Closure closure) {
        assert closure != null
        VulnerabilityDescription vulnerabilityDescription = new VulnerabilityDescription()
        closure.setDelegate(vulnerabilityDescription)
        closure.setResolveStrategy(Closure.OWNER_FIRST)

        closure()
        this.vulnerabilityDescription = closure
    }

    def addStep(HttpSecurityCheckStep step) {
        this.steps.add(step)
    }

    def steps(List<Closure> checks) {
        checks.each { check ->
            HttpSecurityCheckStep step = HttpSecurityCheckStep.create(check)
            addStep(step)
        }
    }

    def steps(HttpSecurityCheckStep... checks) {
        checks.each { check ->
            addStep(check)
        }
    }

    def categories(String... categories) {
        categories.each { category ->
            this.categories << category
        }
    }

    def categories(List<String> categories) {
        this.categories.addAll(categories)
    }
}