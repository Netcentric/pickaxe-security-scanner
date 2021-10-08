/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.maven;

import biz.netcentric.security.checkerdsl.dsl.ScanConfiguration;
import biz.netcentric.security.checkerdsl.dsl.ScanDelegate;
import biz.netcentric.security.checkerdsl.dsl.SecurityCheckProvider;
import biz.netcentric.security.checkerdsl.model.AuthenticationConfig;
import biz.netcentric.security.checkerdsl.model.ScanContext;
import biz.netcentric.security.checkerdsl.report.ReportHandler;
import biz.netcentric.security.checkerdsl.report.Reporter;
import biz.netcentric.security.scans.BuildinAEMChecksLoader;
import com.google.common.collect.Lists;
import org.apache.commons.lang3.StringUtils;
import org.apache.maven.plugins.annotations.Parameter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Scan configuration which can be transformed into a scan delegate which is understood and processable by the security check DSL.
 * A scan configuration may look as follows:
 * <p>
 * &#x3C;configuration&#x3E;
 * &#x3C;scan&#x3E;
 * &#x3C;!-- Target URL --&#x3E;
 * &#x3C;target&#x3E;http://localhost:45181/&#x3C;/target&#x3E;
 * &#x3C;targets&#x3E;
 * &#x3C;location&#x3E;/&#x3C;/target/page123&#x3C;/location&#x3E;
 * &#x3C;location&#x3E;/&#x3C;/target/resource.xyz.png&#x3C;/location&#x3E;
 * &#x3C;/targets&#x3E;
 * &#x3C;!-- Default output location which will be used if the scanReporters do not provide one. --&#x3E;
 * &#x3C;outputLocation&#x3E;/Users/thomas/temp&#x3C;/checks&#x3E;
 * &#x3C;checks&#x3E;
 * &#x3C;location&#x3E;/Users/jenkins/xsschecks&#x3C;/location&#x3E;
 * &#x3C;location&#x3E;/Users/jenkins/dispatcherchecks&#x3C;/location&#x3E;
 * &#x3C;/checks&#x3E;
 * &#x3C;!-- remove if you do not need a scan wide authentication configuration --&#x3E;
 * &#x3C;authentication&#x3E;
 * &#x3C;!-- can be simple or preemptive--&#x3E;
 * &#x3C;authenticationType&#x3E;simple&#x3C;/authenticationType&#x3E;
 * &#x3C;username&#x3E;admin&#x3C;/username&#x3E;
 * &#x3C;password&#x3E;admin&#x3C;/password&#x3E;
 * &#x3C;/authentication&#x3E;
 * &#x3C;!-- Defines the scan scope in term of utilized checks --&#x3E;
 * &#x3C;ignored&#x3E;
 * &#x3C;id&#x3E;nc-235534234&#x3C;/id&#x3E;
 * &#x3C;id&#x3E;nc-xf5534234&#x3C;/id&#x3E;
 * &#x3C;/ignored&#x3E;
 * &#x3C;scope&#x3E;
 * &#x3C;!-- Optional: default is true --&#x3E;
 * &#x3C;runAllChecks&#x3E;false&#x3C;/runAllChecks&#x3E;
 * &#x3C;!-- Optional: setting any category it will disable runAllChecks by setting it to true --&#x3E;
 * &#x3C;categories&#x3E;
 * &#x3C;category&#x3E;xss&#x3C;/category&#x3E;
 * &#x3C;category&#x3E;dispatcher&#x3C;/category&#x3E;
 * &#x3C;/categories&#x3E;
 * &#x3C;names&#x3E;
 * &#x3C;name&#x3E;nc-23434234&#x3C;/name&#x3E;
 * &#x3C;name&#x3E;xyz-2342w23423&#x3C;/name&#x3E;
 * &#x3C;/names&#x3E;
 * &#x3C;/scope&#x3E;
 * &#x3C;!-- Defines how to deal with identified issues in terms of reporting. --&#x3E;
 * &#x3C;scanReporters&#x3E;
 * &#x3C;scanReporter&#x3E;
 * &#x3C;!-- mandatory: examples are e.g. default-console and json-pretty--&#x3E;
 * &#x3C;name&#x3E;json-pretty&#x3C;/name&#x3E;
 * &#x3C;/scanReporter&#x3E;
 * &#x3C;/scanReporters&#x3E;
 * &#x3C;/scan&#x3E;
 * &#x3C;/configuration&#x3E;
 *
 * It requires at least a main target else it is not complete
 */
public class Scan {

    private static final String LEAST_INVASIVE_REPORTER = "default-console";

    @Parameter(property = "target", required = true)
    private String target;

    @Parameter(property = "targets.location", required = false)
    private List<String> targets;

    @Parameter(property = "checks.location", required = false)
    private List<String> checks;

    @Parameter(property = "ignored.id", required = false)
    private List<String> ignored;

    @Parameter(property = "outputLocation", required = true)
    private String outputLocation;

    @Parameter
    private Scope scope;

    @Parameter
    private Authentication authentication;

    @Parameter(property = "scanReporters.scanReporter")
    private List<String> scanReporters;

    public ScanDelegate toScanDelegate(final SecurityCheckProvider securityCheckProvider) {
        assert StringUtils.isNotBlank(getTarget());

        loadBuildInChecks(securityCheckProvider);

        final ScanDelegate scanDelegate = createScanDelegate();
        scanDelegate.setSecurityCheckProviderDelegate(securityCheckProvider);

        loadChecks(scanDelegate);

        initScanScope(scanDelegate);

        final Reporter reporter = getReporterConfiguration();
        scanDelegate.setReporterDelegate(reporter);

        return scanDelegate;
    }

    private ScanDelegate createScanDelegate() {
        final ScanDelegate scanDelegate = new ScanDelegate();

        final List<String> additionalTargets =
                this.targets != null && !this.targets.isEmpty() ? this.targets : Lists.newArrayList();

        final ScanContext scanContext = new ScanContext(this.target, additionalTargets);
        scanDelegate.setTargetContextDelegate(scanContext);

        return scanDelegate;
    }

    private void initScanScope(ScanDelegate scanDelegate) {
        final ScanConfiguration scanConfiguration = getScope() != null ?
                getScope().toScanConfiguration() : new ScanConfiguration();

        if (authentication != null) {
            AuthenticationConfig authConfig = authentication.toAuthenticationConfig();
            scanConfiguration.setAuthConfig(authConfig);
        }

        // running all checks if the scope is not defined.
        if (getScope() == null) {
            scanConfiguration.runAllChecks(true);
        }

        if (this.ignored != null && this.ignored.size() > 0) {
            scanConfiguration.ignored(this.ignored);
        }

        scanDelegate.setConfigDelegate(scanConfiguration);
    }

    private void loadChecks(ScanDelegate scanDelegate) {
        if (this.checks != null && this.checks.size() > 0) {
            scanDelegate.register(this.checks);
        }
    }

    private void loadBuildInChecks(SecurityCheckProvider securityCheckProvider) {
        BuildinAEMChecksLoader buildinChecksLoader = new BuildinAEMChecksLoader();
        buildinChecksLoader.setSecurityCheckProvider(securityCheckProvider);
        buildinChecksLoader.init();
    }


    private Reporter getReporterConfiguration() {
        final List<ReportHandler> providedHandlers = Reporter.provideReportHandlers();
        final Map<String, ReportHandler> mappedHandlers = providedHandlers.stream()
                .collect(Collectors.toMap(handler -> handler.getName(), p -> p));

        final List<String> selected = new ArrayList();
        // check wether we have a config, else we fall back to the least invasive reporter.
        if (getScanReporters() != null) {
            getScanReporters().stream()
                    .filter(sr -> mappedHandlers.containsKey(sr))
                    .map(sr -> {
                        ReportHandler handler = mappedHandlers.get(sr);
                        return handler;
                    })
                    .forEach(handler -> {
                        selected.add(handler.getName());
                        mappedHandlers.put(handler.getName(), handler);
                    });

        } else {
            selected.add(LEAST_INVASIVE_REPORTER);
        }

        Reporter reporter = new Reporter();
        reporter.setOutputLocation(this.outputLocation);
        reporter.setAvailableHandlers(mappedHandlers);

        // as a default we select all handlers
        if (selected.size() == 0) {
            reporter.setSelectedReporterHandlers(Lists.newArrayList(mappedHandlers.keySet()));
        } else {
            reporter.setSelectedReporterHandlers(selected);
        }

        return reporter;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public List<String> getTargets() {
        return targets;
    }

    public void setTargets(List<String> targets) {
        this.targets = targets;
    }

    public List<String> getIgnored() {
        return ignored;
    }

    public void setIgnored(List<String> ignored) {
        this.ignored = ignored;
    }

    public String getOutputLocation() {
        return outputLocation;
    }

    public void setOutputLocation(String outputLocation) {
        this.outputLocation = outputLocation;
    }

    public Scope getScope() {
        return scope;
    }

    public void setScope(Scope scope) {
        this.scope = scope;
    }

    public List<String> getScanReporters() {
        return scanReporters;
    }

    public void setScanReporters(List<String> scanReporters) {
        this.scanReporters = scanReporters;
    }

    public Authentication getAuthentication() {
        return authentication;
    }

    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }

    public List<String> getChecks() {
        return checks;
    }

    public void setChecks(List<String> checks) {
        this.checks = checks;
    }
}
