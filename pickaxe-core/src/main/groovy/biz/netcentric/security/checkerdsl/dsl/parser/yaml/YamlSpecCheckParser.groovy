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
import biz.netcentric.security.checkerdsl.dsl.parser.SpecParser
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheckStep
import groovy.util.logging.Slf4j
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.Constructor

/**
 * Parses a check spec. The YamlSpecCheckParser reads a YAML files and translates it into a spec model first.
 * The model is then used to configure the HttpSecurityCheck object.
 */
@Slf4j
class YamlSpecCheckParser implements SpecParser {

    @Override
    List<HttpSecurityCheck> createCheck(Spec spec) {
        Yaml yaml = new Yaml(new Constructor(CheckSpec.class))
        CheckSpec checkSpec = yaml.load(spec.content)

        log.debug checkSpec.toString()

        return createSecurityCheck(checkSpec)
    }

    private List<HttpSecurityCheck> createSecurityCheck(CheckSpec checkSpec) {
        assert checkSpec != null
        assert checkSpec.getSteps() != null

        HttpSecurityCheck httpSecurityCheck = new HttpSecurityCheck([id: checkSpec.id])

        if (checkSpec.getVulnerability() != null) {
            Vulnerability vulnerability = checkSpec.getVulnerability()
            httpSecurityCheck.vulnerability vulnerability.toClosure()
        }

        if (checkSpec.getCategories() != null) {
            httpSecurityCheck.setCategories(checkSpec.getCategories())
        }

        // can never be null due to the guard clause
        checkSpec.getSteps().each { step ->
            HttpSecurityCheckStep securityCheckStep = HttpSecurityCheckStep.create step.toSecurityCheckClosure()
            httpSecurityCheck.addStep securityCheckStep
        }

        log.debug httpSecurityCheck.toString()

        List<HttpSecurityCheck> list = new ArrayList<HttpSecurityCheck>()
        list.add((HttpSecurityCheck) httpSecurityCheck)
        return list
    }
}
