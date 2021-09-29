package biz.netcentric.security.checkerdsl.dsl.parser.groovy

import groovy.util.logging.Slf4j
import org.codehaus.groovy.control.CompilerConfiguration
import org.codehaus.groovy.control.customizers.ImportCustomizer

@Slf4j
class GroovySourceParser {

    List<String> DEFAULT_IMPORTS = ['biz.netcentric.security.checkerdsl.dsl.securitycheck','biz.netcentric.security.checkerdsl.dsl', 'biz.netcentric.security.checkerdsl.model', 'biz.netcentric.security.checkerdsl.payload']

    Object evaluateSource(String sourceCode) {
        ImportCustomizer importCustomizer = new ImportCustomizer()
        importCustomizer.addStarImports(DEFAULT_IMPORTS.toArray(new String[DEFAULT_IMPORTS.size()]))

        CompilerConfiguration compilerConfig = new CompilerConfiguration()
        compilerConfig.addCompilationCustomizers(importCustomizer)

        GroovyShell groovyShell = new GroovyShell(compilerConfig)
        return groovyShell.evaluate("${sourceCode}")
    }
}
