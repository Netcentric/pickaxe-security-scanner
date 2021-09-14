package biz.netcentric.security.scans

import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.CheckExecutionResult
import biz.netcentric.security.checkerdsl.model.ScanContext
import org.junit.Assert
import org.junit.jupiter.api.Test

import static org.mockserver.model.HttpRequest.request
import static org.mockserver.model.HttpResponse.response

/**
 * Test is based on http://www.mock-server.com/mock_server/initializing_expectations.html
 */
class ContentGrabbingCheckTest implements MockServerTrait {

    String CHECK_UNDER_TEST = "misconfiguration/content-grabbing-check.groovy"

    @Test
    void "check content grabbing selectors"() {
        HttpSecurityCheck check = loadSingleCheck("nc-OYJ7eLvR", CHECK_UNDER_TEST)
        CheckExecutionResult result = check createHttpClient(), new ScanContext("http://localhost:" + DEFAULT_PORT + "/content/de/we-retail.html")

        Assert.assertEquals 1, result.issues.size()
    }

    @Override
    void setExpectations() {
        mockServerClient()
                .when(
                        request()
                                .withMethod("GET")
                                .withPath("/content/de/we-retail.blueprint.json")
                )
                .respond(
                        response()
                                .withBody("{ jcr:createdBy: admin, jcr:lastModifiedBy: admin }")
                )
    }

    @Override
    void resetExpectations() {
        reset("/content/de/we-retail.blueprint.json")
    }
}
