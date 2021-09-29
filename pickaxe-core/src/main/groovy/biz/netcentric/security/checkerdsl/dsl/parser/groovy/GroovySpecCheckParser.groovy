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

package biz.netcentric.security.checkerdsl.dsl.parser.groovy

import biz.netcentric.security.checkerdsl.config.Spec
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.dsl.parser.SpecParser
import groovy.util.logging.Slf4j
import org.codehaus.groovy.control.CompilerConfiguration
import org.codehaus.groovy.control.customizers.ImportCustomizer

@Slf4j
class GroovySpecCheckParser implements SpecParser {

    @Override
    List<HttpSecurityCheck> createCheck(Spec script) {
        String scriptSource = script.content
        GroovySourceParser groovyParser = new GroovySourceParser()
        Object checkObj = groovyParser.evaluateSource(scriptSource)

        if(checkObj instanceof List){
            return (List<HttpSecurityCheck>) checkObj
        }else{
            List<HttpSecurityCheck> list = new ArrayList<HttpSecurityCheck>()
            list.add((HttpSecurityCheck) checkObj)
            return list
        }
    }
}
