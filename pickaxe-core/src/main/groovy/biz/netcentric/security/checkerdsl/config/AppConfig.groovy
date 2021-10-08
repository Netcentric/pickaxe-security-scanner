/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.config

/**
 * Reads and parses an application configs from a location such as an URL or the classpath
 * to setup the security tests.
 */
@SuppressWarnings('GroovyAssignabilityCheck')
class AppConfig {

    List<ConfigObject> configs = []

    AppConfig(URL configLocation) {
        configs << new ConfigSlurper().parse(configLocation)
    }

    AppConfig(List<URL> configLocations) {
        configLocations.each { location ->
            configs << new ConfigSlurper().parse(location)
        }
    }

    static AppConfig fromClasspath(String path) {
        new AppConfig(AppConfig.getResource(path))
    }

    static AppConfig fromClasspath(List<String> paths) {
        def resources = []
        paths.each { path ->
            resources << AppConfig.getResource(path)
        }

        new AppConfig(resources)
    }
}
