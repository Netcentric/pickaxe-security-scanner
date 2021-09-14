package biz.netcentric.security.scans

import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.CheckExecutionResult
import biz.netcentric.security.checkerdsl.model.ScanContext
import org.junit.Assert
import org.junit.jupiter.api.Test

import static org.mockserver.model.HttpRequest.request
import static org.mockserver.model.HttpResponse.response

class QueryBuilderExposedCheckTest implements MockServerTrait {

    String CHECK_ID = "nc-s55ibLtb"

    String CHECK_UNDER_TEST = "dispatcher/querybuilder-exposed.groovy"

    @Test
    void "check if plain querybuilder with bypass is accessible"() {
        HttpSecurityCheck check = loadSingleCheck(CHECK_ID, CHECK_UNDER_TEST)

        mockServerClient()
                .when(
                        request()
                                .withMethod("GET")
                                .withPath("/bin/querybuilder.json/a.css")
                )
                .respond(
                        response()
                                .withBody("{\"success\":true,\"results\":0,\"total\":0,\"more\":false,\"offset\":0,\"hits\":[]}")
                )

        CheckExecutionResult result = check createHttpClient(), new ScanContext("http://localhost:" + DEFAULT_PORT + "/bin/querybuilder.json/a.css")

        Assert.assertTrue result.hasFindings()
    }

    @Test
    void "check if plain querybuilder is accessible"() {
        mockServerClient()
                .when(
                        request()
                                .withMethod("GET")
                                .withPath("/bin/querybuilder.json")
                )
                .respond(
                        response()
                                .withBody("{\"success\":true,\"results\":0,\"total\":0,\"more\":false,\"offset\":0,\"hits\":[]}")
                )

        HttpSecurityCheck check = loadSingleCheck(CHECK_ID, CHECK_UNDER_TEST)
        CheckExecutionResult result = check createHttpClient(), new ScanContext("http://localhost:" + DEFAULT_PORT + "/bin/querybuilder.json")

        Assert.assertTrue result.hasFindings()
    }

    @Override
    void setExpectations() {
    }

    @Override
    void resetExpectations() {
        reset("/bin/querybuilder.json")
        reset("/bin/querybuilder.json/a.css")
    }
}