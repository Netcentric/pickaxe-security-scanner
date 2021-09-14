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
class AuditServletCheckTest implements MockServerTrait {

    String CHECK_UNDER_TEST = "misconfiguration/audit-servlet-check.groovy"

    @Test
    void "detect audit paths"() {
        HttpSecurityCheck check = loadSingleCheck("nc-XNBpkC0s", CHECK_UNDER_TEST)
        CheckExecutionResult result = check createHttpClient(), new ScanContext("http://localhost:" + DEFAULT_PORT + "/")

        Assert.assertEquals 2, result.issues.size()
    }

    @Override
    void setExpectations() {
        mockServerClient().when(
                request()
                        .withMethod("GET")
                        .withPath("/bin/msm/audit")
        )
                .respond(
                        response()
                                .withBody("{ results: 1 }")
                )
    }

    @Override
    void resetExpectations() {
        reset("/bin/msm/audit")
    }
}
