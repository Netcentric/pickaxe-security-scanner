package biz.netcentric.security.checkerdsl.dsl.parser.groovy

import biz.netcentric.security.checkerdsl.config.Spec
import biz.netcentric.security.checkerdsl.dsl.Scan
import biz.netcentric.security.checkerdsl.dsl.ScanDelegate
import biz.netcentric.security.checkerdsl.dsl.SecurityCheckProvider
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import groovy.util.logging.Slf4j

@Slf4j
class GroovySpecScanParser {

    ScanDelegate createScan(Spec spec, SecurityCheckProvider securityCheckProvider) {

        String scriptSource = spec.content
        GroovySourceParser groovyParser = new GroovySourceParser()
        Object checkObj = groovyParser.evaluateSource(scriptSource)

        return Scan.create(securityCheckProvider, checkObj)
    }

    ScanDelegate createScan(Spec spec, SecurityCheckProvider securityCheckProvider, List<HttpSecurityCheck> buildinChecks) {
        ScanDelegate scanDelegate  = createScan(spec, securityCheckProvider)
        buildinChecks.each {check ->
            scanDelegate.register(check)
        }

        return scanDelegate
    }
}
