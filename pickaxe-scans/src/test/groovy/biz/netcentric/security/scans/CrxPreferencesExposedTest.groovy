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
 * /crx/de/setPreferences.jsp?keymap=<sdadas expects
 * statsucode: 400
 * and
 * response: Invalid keymap: A JSONObject text must begin with '{' at character 1 of <azgqr>
 *
 */
class CrxPreferencesExposedTest implements MockServerTrait {

    String CHECK_UNDER_TEST = "xss/crx-preferences-xss.groovy"

    String EXPECTED_RESULT = '''Invalid keymap: A JSONObject text must begin with '{' at character 1 of <azgqr>'''

    @Test
    void "detect keymap post servlet"() {
        HttpSecurityCheck check = loadSingleCheck("nc-I56crx6W", CHECK_UNDER_TEST)
        CheckExecutionResult result = check createHttpClient(), new ScanContext("http://localhost:" + DEFAULT_PORT + "/")

        Assert.assertTrue result.hasFindings()
    }

    @Override
    void setExpectations() {
        mockServerClient().when(
                request()
                        .withMethod("GET")
                        .withPath("/crx/de/setPreferences.jsp")
                        .withQueryStringParameters(
                                Parameter.param("keymap", "<azgqr>"),
                                Parameter.param("language", "0")
                        ))
                .respond(
                        response()
                                .withStatusCode(400)
                                .withBody(EXPECTED_RESULT)
                )
    }

    @Override
    void resetExpectations() {
        reset("/crx/de/setPreferences.jsp")
    }
}
