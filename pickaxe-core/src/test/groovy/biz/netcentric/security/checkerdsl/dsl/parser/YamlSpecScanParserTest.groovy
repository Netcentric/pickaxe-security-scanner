package biz.netcentric.security.checkerdsl.dsl.parser

import biz.netcentric.security.checkerdsl.config.Spec
import biz.netcentric.security.checkerdsl.config.SpecFormat
import biz.netcentric.security.checkerdsl.dsl.ScanConfiguration
import biz.netcentric.security.checkerdsl.dsl.ScanDelegate
import biz.netcentric.security.checkerdsl.dsl.SecurityCheckProvider
import biz.netcentric.security.checkerdsl.dsl.parser.yaml.YamlSpecScanParser
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.AuthType
import biz.netcentric.security.checkerdsl.model.AuthenticationConfig
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import static org.junit.Assert.*

class YamlSpecScanParserTest {

    static final String TEST_FILE = "/config-loader-tests/scan/scan-definition-test.yaml"

    SecurityCheckProvider securityCheckProvider

    Spec scanSpec

    YamlSpecScanParser parser

    List<HttpSecurityCheck> buildinChecks = []

    @BeforeEach
    void prepareScan(){
        parser = new YamlSpecScanParser()
        securityCheckProvider = new SecurityCheckProvider()
        def resource = this.getClass().getResource(TEST_FILE)
        File file = new File(resource.toURI())
        this.buildinChecks << new HttpSecurityCheck(id: "demo1", name: "demo1")
        this.buildinChecks << new HttpSecurityCheck(id: "demo2", name: "demo2")

        scanSpec = new Spec(content: file.text, specFormat: SpecFormat.YAML, location: TEST_FILE, name: "scan-definition-test.yaml")
    }

    @Test
    void hasExpectedAuthenticationConfig() {
        ScanDelegate scan = parser.createScan(scanSpec, securityCheckProvider, [])
        AuthenticationConfig authConfig = scan.getConfigDelegate().getAuthConfig()
        assertEquals  "admin", authConfig.getUsername()
        assertEquals  "admin123", authConfig.getPassword()
        assertEquals  AuthType.SIMPLE, authConfig.getAuthenticationType()
        assertEquals  "none", authConfig.getToken()
    }

    @Test
    void hasExpectedScanConfiguration() {
        ScanDelegate scan = parser.createScan(scanSpec, securityCheckProvider, [])
        ScanConfiguration scanConfiguration = scan.getConfigDelegate()

        def expectedCategories = ["xss", "crx"]
        assertEquals expectedCategories.join(","), scanConfiguration.getCategories().join(",")

        def expectedNames = ["xxsasd","xysasd"]
        assertEquals expectedNames.join(","), scanConfiguration.getNames().join(",")

        assertEquals false, scanConfiguration.getAll()
    }

    @Test
    void loadsBuildInHttpSecurityChecks() {
        ScanDelegate scan = parser.createScan(scanSpec, securityCheckProvider, this.buildinChecks)
        ScanConfiguration scanConfiguration = scan.getConfigDelegate()
        // clear existing configs
        scanConfiguration.categories([])
        scanConfiguration.names([])

        // we need to load it from the SecurityCheckProvider as the actual scan does not know about the internal details in check level yet
        // it does not get evaluated before execution of the scan
        List<HttpSecurityCheck> allLoadedChecks = scan.getSecurityCheckProviderDelegate().getAllChecks()

        // expect the default ones and one additional from external config
        assertEquals 3, allLoadedChecks.size()
        this.buildinChecks.each {check ->
            assertTrue allLoadedChecks.contains(check)
        }
    }

}
