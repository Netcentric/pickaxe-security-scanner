/*
 * (C) Copyright 2020 Netcentric AG.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.scans

import biz.netcentric.security.checkerdsl.dsl.SecurityCheckProvider
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import groovy.util.logging.Slf4j

/**
 * Loads all Adobe Experience Manager related checks which are shipped in the resources section of this maven module.
 */
@Slf4j
class BuildinAEMChecksLoader {

    SecurityCheckProvider securityCheckProvider

    List<String> BUILD_IN_CONFIGS = ["/misconfiguration", "/dispatcher", "/xss", "/accesscontrol", "/crx", "/xxe"]

    def init() {
        BUILD_IN_CONFIGS.each {
            URL resource = this.getClass().getResource(it)
            log.info "Loading build in AEM checks from " + resource.toString()
            securityCheckProvider.initializeCheckFromFileSystem(it)
        }
    }

    def registerManually(HttpSecurityCheck check) {
        assert securityCheckProvider != null
        assert check != null

        securityCheckProvider.add(check)
        log.info "Registered Check: {} ", check.name
    }

    def getRegisteredChecks() {
        if (securityCheckProvider != null) {
            return securityCheckProvider.getAllChecks()
        }
        return []
    }
}


