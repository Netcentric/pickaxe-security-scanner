package biz.netcentric.security.scans

import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.CheckExecutionResult
import biz.netcentric.security.checkerdsl.model.ScanContext
import org.junit.Assert
import org.junit.jupiter.api.Test
import org.mockserver.model.Parameter

import static org.mockserver.model.HttpRequest.request
import static org.mockserver.model.HttpResponse.response

/**
 * Test is based on http://www.mock-server.com/mock_server/initializing_expectations.html
 * /libs/dam/merge/metadata.html?path=/etcy expects
 * statuscode: 200
 * and
 * response: {"assetPaths":["/etcy<"],"metadata":{}}
 * and Content-Type: application(json is missing
 *
 */
class DamMetadataMergeXssTest implements MockServerTrait {

    String CHECK_UNDER_TEST = "xss/dam-metadata-merge-xss.groovy"

    String EXPECTED_RESULT = '''{"assetPaths":["/etcy<"],"metadata":{}}'''

    @Test
    void "detect json response with special char and missing content type"() {
        HttpSecurityCheck check = loadSingleCheck("nc-I56crx6W", CHECK_UNDER_TEST)
        CheckExecutionResult result = check createHttpClient(), new ScanContext("http://localhost:" + DEFAULT_PORT + "/")

        Assert.assertTrue result.hasFindings()
    }

    @Override
    void setExpectations() {
        mockServerClient().when(
                request()
                        .withMethod("GET")
                        .withPath("/libs/dam/merge/metadata.html")
                        .withQueryStringParameters(
                                Parameter.param("path", "/etc<")
                        ))
                .respond(
                        response()
                                .withStatusCode(200)
                                .withBody(EXPECTED_RESULT)
                )
    }

    @Override
    void resetExpectations() {
        reset("/libs/dam/merge/metadata.html")
    }
}
