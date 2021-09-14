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

import biz.netcentric.security.checkerdsl.config.FileSystemSpecLoader
import biz.netcentric.security.checkerdsl.config.Spec
import biz.netcentric.security.checkerdsl.config.SpecFormat
import biz.netcentric.security.checkerdsl.dsl.parser.groovy.GroovySpecCheckParser
import biz.netcentric.security.checkerdsl.dsl.parser.SpecParser
import biz.netcentric.security.checkerdsl.dsl.parser.yaml.YamlSpecCheckParser
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import com.google.common.collect.ArrayListMultimap
import com.google.common.collect.Multimap

/**
 * Registers, loads and provides security checks which are typically imported as scripted specs
 * from a defined URI or path and transformed to a groovy model or shell.
 * Each check spec can by either a groovy script based on the engine#s DSL or a YAML spec.
 *
 * It can preregister certain imports internally.
 * Can also be pre-created and then injected into a {@link Scan}
 */
class SecurityCheckProvider {

    Multimap<String, HttpSecurityCheck> checkClosures = ArrayListMultimap.create()

    FileSystemSpecLoader fsLoader

    Map<SpecFormat, SpecParser> specParsers = [:]

    SecurityCheckProvider() {
        fsLoader = new FileSystemSpecLoader()
        specParsers.put SpecFormat.GROOVY, new GroovySpecCheckParser()
        specParsers.put SpecFormat.YAML, new YamlSpecCheckParser()
    }

    void initializeCheckFromFileSystem(String location) {
        List<Spec> scripts = fsLoader.loadFromLocation(location)
        this.loadSecurityChecks(scripts)
    }

    void initializeCheckFromFileSystem(URI uri) {
        List<Spec> scripts = fsLoader.loadFromLocation(uri)
        this.loadSecurityChecks(scripts)
    }

    void initializeCheckFromFileSystem(URL location) {
        def uri = location.toURI()
        List<Spec> scripts = fsLoader.loadFromLocation(uri)
        this.loadSecurityChecks(scripts)
    }

    private void loadSecurityChecks(List<Spec> scripts) {
        scripts.each { script ->

            SpecParser specParser = specParsers.get(script.specFormat)
            List<HttpSecurityCheck> checkClosures = specParser.createCheck(script)

            if (checkClosures != null) {
                checkClosures.each {checkClosure->
                    add(checkClosure)
                }
            }
        }
    }

    List<HttpSecurityCheck> getAllChecks() {
        return new ArrayList<HttpSecurityCheck>(checkClosures.values())
    }

    List<HttpSecurityCheck> getByCategory(List<String> categories) {
        List<HttpSecurityCheck> selectedChecks = []
        checkClosures.values().each { check ->
            check.categories.each { category ->
                if (categories.contains(category)) {
                    selectedChecks << check
                }
            }
        }

        selectedChecks
    }

    List<HttpSecurityCheck> getByName(List<String> names) {
        List<HttpSecurityCheck> selectedChecks = []
        checkClosures.values().each { check ->
            if (names.contains(check.getId())) {
                selectedChecks << check
            }
        }

        selectedChecks
    }

    List<String> getCheckIds() {
        checkClosures.keys().asList()
    }

    void add(HttpSecurityCheck checkClosure) {
        checkClosures.put(checkClosure.id, checkClosure)
    }

    void remove(String id) {
        checkClosures.remove(id)
    }
}