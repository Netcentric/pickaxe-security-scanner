package biz.netcentric.security.checkerdsl.dsl.parser

import biz.netcentric.security.checkerdsl.config.Spec
import biz.netcentric.security.checkerdsl.config.SpecFormat
import biz.netcentric.security.checkerdsl.dsl.detection.DetectionRule
import biz.netcentric.security.checkerdsl.dsl.parser.yaml.YamlSpecCheckParser
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheckStep
import biz.netcentric.security.checkerdsl.model.Severity
import biz.netcentric.security.checkerdsl.model.VulnerabilityDescription
import org.junit.Assert
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class YamlSpecCheckParserTest {

    static final String TEST_FILE = "/config-loader-tests/yaml/yaml-parser-check.yaml"

    static final String BASE_URL = "http;//www.example.com"

    List<HttpSecurityCheck> checks

    @BeforeEach
    void prepareScan(){
        Spec spec = loadYamlSpec()
        YamlSpecCheckParser parser = new YamlSpecCheckParser()
        this.checks = parser.createCheck(spec)
    }

    private Spec loadYamlSpec() {
        def resource = this.getClass().getResource(TEST_FILE)
        File file = new File(resource.toURI())
        Spec spec = new Spec(specFormat: SpecFormat.YAML, content: file.text, location: TEST_FILE, name: file.name)
        spec
    }

    @Test
    void generalCheckInformationIsCorrect() {
        HttpSecurityCheck httpSecurityCheck = checks.get(0)

        Assert.assertEquals "yaml-test-1", httpSecurityCheck.getId()

        Assert.assertEquals 2, httpSecurityCheck.getCategories().size()
        Assert.assertTrue httpSecurityCheck.getCategories().contains("dispatcher")
        Assert.assertTrue httpSecurityCheck.getCategories().contains("checkerdsl")
    }

    @Test
    void vulnerabilityDescriptionInitialized() {
        HttpSecurityCheck httpSecurityCheck = checks.get(0)

        Closure<VulnerabilityDescription> vulnerabilityDescription = httpSecurityCheck.getVulnerabilityDescription()

        Assert.assertEquals "Data manipulation", vulnerabilityDescription.getName()
        Assert.assertTrue vulnerabilityDescription.getDescription().startsWith("Upload")
        Assert.assertTrue vulnerabilityDescription.getRemediation().startsWith("Block")
        Assert.assertEquals Severity.HIGH.toString(), vulnerabilityDescription.getSeverity()
        Assert.assertEquals "cwe-2132", vulnerabilityDescription.getCve()

    }

    @Test
    void stepsInitialized() {
        HttpSecurityCheck httpSecurityCheck = checks.get(0)
        HttpSecurityCheckStep step = httpSecurityCheck.getSteps().get(0)

        Assert.assertEquals "get Data", step.getName()
        // test method on request delegate Assert.assertEquals "GET", step.getMethod()
        Assert.assertTrue step.getPaths().contains("/crx/de")
        Assert.assertTrue step.getPaths().contains("/crx/de/index.jsp")
        Assert.assertEquals "Basic xyz", step.getAuthenticationHeaders().get(0).getValue()
        Assert.assertEquals "example.com", step.getRequestHeaders().get("host")
        Assert.assertEquals "referer.example.com", step.getRequestHeaders().get("Referer")
        Assert.assertEquals "value1", step.getParams().get("param1")
        Assert.assertEquals "value2", step.getParams().get("param2")

        step = httpSecurityCheck.getSteps().get(1)

        Assert.assertEquals "post data", step.getName()

        Assert.assertTrue step.getPaths().contains("/webdav")
        Assert.assertTrue step.getPaths().contains("/webdav/xxx")
        Assert.assertEquals "Basic xyz", step.getAuthenticationHeaders().get(0).getValue()
        Assert.assertEquals "example.com", step.getRequestHeaders().get("host")
        Assert.assertEquals "referer.example.com", step.getRequestHeaders().get("Referer")
        Assert.assertEquals "value1", step.getParams().get("param1")
        Assert.assertEquals "value2", step.getParams().get("param2")
    }

    @Test
    void requestStepsHaveCorrectMethod() {
        HttpSecurityCheck httpSecurityCheck = checks.get(0)
        HttpSecurityCheckStep step = httpSecurityCheck.getSteps().get(0)

        Assert.assertEquals "GET", step.getMethod()

        step = httpSecurityCheck.getSteps().get(1)

        Assert.assertEquals "POST", step.getMethod()
    }

    @Test
    void detectionRulesInitialized() {
        HttpSecurityCheck httpSecurityCheck = checks.get(0)
        HttpSecurityCheckStep step = httpSecurityCheck.getSteps().get(0)

        Closure<DetectionRule> rule = step.getDetectionRule()
        Assert.assertTrue rule instanceof Closure
    }

    @Test
    void authenticationHeadersInitialized() {

    }
}
