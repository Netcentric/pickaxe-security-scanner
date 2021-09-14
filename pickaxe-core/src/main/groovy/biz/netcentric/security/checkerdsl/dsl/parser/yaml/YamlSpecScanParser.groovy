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
package biz.netcentric.security.checkerdsl.dsl.parser.yaml

import biz.netcentric.security.checkerdsl.config.Spec
import biz.netcentric.security.checkerdsl.dsl.Scan
import biz.netcentric.security.checkerdsl.dsl.ScanDelegate
import biz.netcentric.security.checkerdsl.dsl.SecurityCheckProvider
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
    ScanDelegate createScan(Spec spec, SecurityCheckProvider securityCheckProvider) {
        Yaml yaml = new Yaml(new Constructor(ScanSpec.class))
        ScanSpec scanSpec = yaml.load(spec.content)

        log.debug scanSpec.toString()

        return createScanDelegate(scanSpec, securityCheckProvider)
    }

    /**
     * Provides the scan delegate but buildin checks are still missing as they are not contained inside the core lib.
     * To init them the check provider has to be injected.
     */
    private ScanDelegate createScanDelegate(ScanSpec scanSpec, SecurityCheckProvider securityCheckProvider) {
        assert scanSpec != null
        assert scanSpec.getTarget() != null
        assert scanSpec.getReporter() != null
        assert scanSpec.getReporter().getHandlers() != null
        assert scanSpec.getReporter().getHandlers().size() > 0

        AuthenticationConfig authenticationConfig = null

        if (scanSpec.getAuthentication() != null) {
            Authentication authentication = scanSpec.getAuthentication()

            AuthType authType = authentication.getAuthenticationType() == "preemptive" ? AuthType.PRE_EMPTIVE : AuthType.SIMPLE
            String username = authentication.getUsername()?.trim() ? authentication.getUsername() : ""
            String password = authentication.getPassword()?.trim() ? authentication.getPassword() : ""
            String token = authentication.getToken()?.trim() ? authentication.getToken() : ""

            authenticationConfig = new AuthenticationConfig(authenticationType: authType, username: username, password: password, token: token)
        }

        boolean all = scanSpec.getScanConfig().getRunAllChecks()

        def checksConfiguration = {

            authentication authenticationConfig

            runAllChecks all
        }

        if (scanSpec.getScanConfig().getCategories().size() > 0) {
            checksConfiguration = checksConfiguration << {
                categories(scanSpec.getScanConfig().getCategories())
            }
        }

        if (scanSpec.getScanConfig().getNames().size() > 0) {
            checksConfiguration = checksConfiguration << {
                names(scanSpec.getScanConfig().getNames())
            }
        }

        def reporter = {
            register(scanSpec.getReporter().getHandlers())
            setOutputLocation(scanSpec.getReporter().getOutputFolder())
        }

        ScanDelegate scanDelegate = Scan.create(securityCheckProvider, {})
        scanDelegate.target(scanSpec.target)
        scanDelegate.config(checksConfiguration)

        if (scanSpec.scanConfig.getLoadFrom() != null) {
            scanDelegate.register(scanSpec.scanConfig.getLoadFrom())
        }

        scanDelegate.reporter(reporter)

        return scanDelegate
    }
}
