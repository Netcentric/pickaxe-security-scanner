/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.dsl.parser.yaml

import biz.netcentric.security.checkerdsl.config.Spec
import biz.netcentric.security.checkerdsl.dsl.Scan
import biz.netcentric.security.checkerdsl.dsl.ScanDelegate
import biz.netcentric.security.checkerdsl.dsl.SecurityCheckProvider
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.AuthType
import biz.netcentric.security.checkerdsl.model.AuthenticationConfig
import groovy.util.logging.Slf4j
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.Constructor

/**
 * Parses a scan spec. The YamlSpecScanParser reads a YAML files and translates it into a spec model first.
 * The model is then used to configure the Scan object.
 */
@Slf4j
class YamlSpecScanParser {

    /**
     * Provides the Scan object.
     * Buildin checks are not assigned if the security check provider does not provide them, despite the ones defined in the spec's loadFrom location.
     *
     * @param spec Spec describing the scan
     * @param securityCheckProvider SecurityCheckProvider which has to be initialized with the buildin checks
     * @return Scan
     */
    ScanDelegate createScan(Spec spec, SecurityCheckProvider securityCheckProvider,  List<HttpSecurityCheck> buildinChecks) {
        Yaml yaml = new Yaml(new Constructor(ScanSpec.class))
        ScanSpec scanSpec = yaml.load(spec.content)

        log.debug scanSpec.toString()

        return createScanDelegate(scanSpec, securityCheckProvider, buildinChecks)
    }

    /**
     * Provides the scan delegate but buildin checks are still missing as they are not contained inside the core lib.
     * To init them the check provider has to be injected.
     */
    private ScanDelegate createScanDelegate(ScanSpec scanSpec, SecurityCheckProvider securityCheckProvider,  List<HttpSecurityCheck> buildinChecks) {
        assert scanSpec != null
        assert scanSpec.getTarget() != null
        assert scanSpec.getReporter() != null
        assert scanSpec.getReporter().getHandlers() != null
        assert scanSpec.getReporter().getHandlers().size() > 0

        // Creates the ScanDelegate wheh is actually executed
        // it get's configured below
        ScanDelegate scanDelegate = Scan.create(securityCheckProvider, {})

        // define the scan target ...
        if(scanSpec.getTargets() == null || scanSpec.getTargets().isEmpty()){
            scanDelegate.target(scanSpec.getTarget())
        }else{
            scanDelegate.target(scanSpec.getTarget(), scanSpec.getTargets())
        }

        if(scanSpec.getScanConfig().getBuildIn()){
            buildinChecks.each {check ->
                scanDelegate.register(check)
            }
        }

        // Load external checks if available
        List<String> registeredLocations = scanSpec.getRegister()
        if (registeredLocations != null && !registeredLocations.isEmpty()) {
            scanDelegate.register(registeredLocations)
        }

        //Authentication Config
        AuthenticationConfig authenticationConfig = null
        if (scanSpec.getScanConfig().getAuthentication() != null) {
            Authentication authentication = scanSpec.getScanConfig().getAuthentication()

            AuthType authType = authentication.getAuthenticationType() == "preemptive" ? AuthType.PRE_EMPTIVE : AuthType.SIMPLE
            String username = authentication.getUsername()?.trim() ? authentication.getUsername() : ""
            String password = authentication.getPassword()?.trim() ? authentication.getPassword() : ""
            String token = authentication.getToken()?.trim() ? authentication.getToken() : ""

            authenticationConfig = new AuthenticationConfig(authenticationType: authType, username: username, password: password, token: token)
        }

        // define the scan configuration ... TODO networking settings
        ScanConfig scanConfig = scanSpec.getScanConfig()
        boolean all = scanConfig.getRunAllChecks()

        def checksConfiguration = {

            authentication authenticationConfig

            runAllChecks all
        }

        if (scanConfig.getCategories().size() > 0) {
            checksConfiguration = checksConfiguration << {
                categories(scanConfig.getCategories())
            }
        }

        if (scanConfig.getCheckIds().size() > 0) {
            checksConfiguration = checksConfiguration << {
                names(scanConfig.getCheckIds())
            }
        }

        if(scanConfig.getFalsePositives().size() > 0) {
            checksConfiguration = checksConfiguration << {
                falsePositives(scanConfig.getFalsePositives())
            }
        }

        // exposed networking config is limited right now as we did not have the need to deviate from defaults anywhere
        if(scanConfig.getConnectionPoolSize()) {
            checksConfiguration = checksConfiguration << {
                connectionPoolSize(scanConfig.getConnectionPoolSize())
            }
        }

        if(scanConfig.getCheckThrottlingMillis()) {
            checksConfiguration = checksConfiguration << {
                checkThrottlingMillis(Long.valueOf(scanConfig.getCheckThrottlingMillis()))
            }
        }

        // define the reporting behaviour
        def reporter = {
            register(scanSpec.getReporter().getHandlers())
            setOutputLocation(scanSpec.getReporter().getOutputFolder())
        }


        scanDelegate.config(checksConfiguration)

        scanDelegate.reporter(reporter)

        return scanDelegate
    }
}
