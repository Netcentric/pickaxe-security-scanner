/*
 * (C) Copyright 2020 Netcentric AG.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl

import biz.netcentric.security.checkerdsl.commandlinetools.CheckIDGenerator
import biz.netcentric.security.checkerdsl.config.FileSystemSpecLoader
import biz.netcentric.security.checkerdsl.config.Spec
import biz.netcentric.security.checkerdsl.config.SpecFormat
import biz.netcentric.security.checkerdsl.dsl.ScanDelegate
import biz.netcentric.security.checkerdsl.dsl.SecurityCheckProvider
import biz.netcentric.security.checkerdsl.dsl.parser.yaml.YamlSpecScanParser
import biz.netcentric.security.checkerdsl.model.Issue
import groovy.util.logging.Slf4j

/**
 * Public interface of the security checker DSL
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 03/2019
 */
@Slf4j
class ScanClient {

    SecurityCheckProvider securityCheckProvider = new SecurityCheckProvider()

    FileSystemSpecLoader fsLoader = new FileSystemSpecLoader()


    /**
     * Executes a scan defined by an external scan definition spec.
     *
     * @param scanFileLocation Some location on the filesystem
     * @param securityCheckProvider Must be provided by the caller as the caller has to define if buildin checks are allowed
     * @return List of issues
     */
    List<Issue> executeScan(String scanFileLocation, SecurityCheckProvider securityCheckProvider) {
        List<Spec> specs = fsLoader.loadFromLocation(scanFileLocation)

        if (specs.size() == 0) {
            log.info "No specs found at ${scanFileLocation}."
            return
        }

        if (specs.size() > 1) {
            log.info "Found ${specs.size()} specs. Only the first one is used."
        }

        // we take the first one
        Spec spec = specs.get(0)
        if (spec.getSpecFormat() != SpecFormat.YAML) {
            log.info "File ${scanFileLocation} is not a YAML spec. Only the YAML format is currently supported for external scan configurations."
            return
        }
        YamlSpecScanParser yamlParser = new YamlSpecScanParser()()
        ScanDelegate scan = yamlParser.createCheck(spec, securityCheckProvider)

        executeScan(scan)
    }

    /**
     * Executes a pre configured scan.
     *
     * @param scan
     * @return List of issues
     */
    List<Issue> executeScan(ScanDelegate scan) {
        List<Issue> issues = scan()

        issues.each {
            log.debug it.toString()
        }

        issues
    }

    String provideUniqueCheckId(SecurityCheckProvider securityCheckProvider) {
        CheckIDGenerator idGenerator = new CheckIDGenerator()
        List<String> ids = securityCheckProvider.getCheckIds()

        String id = idGenerator.createUniqueId()
        while (ids.contains(id)) {
            id = idGenerator.createUniqueId()
            println id
        }

        id
    }
}
