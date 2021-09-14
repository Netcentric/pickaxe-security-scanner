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
 * .cqactions.json?authorizableId=everyone&predicate=useradmin&depth=0&path=/&_charset_=utf8&depth=4
 * /.cqactions.json?authorizableId=anonymous&predicate=useradmin&depth=0&path=/content&_charset_=utf8
 */
class CQActionsExposedTest implements MockServerTrait {

    String CHECK_UNDER_TEST = "dispatcher/cqactions-exposed.groovy"

    String EXPECTED_RESULT ='''{"entries":[{"name":"","name_xss":"","_id":"/","_parent":null,"_is_leaf":false,"authorizableId":"everyone","declared":{"modify":{},"replicate":{},"read":{},"create":{},"delete":{},"acl_read":{},"acl_edit":{}},"canreadac":false,"canwriteac":false,"children":["/crx","/content","/bin"]}],"results":1}'''

    @Test
    void "detect cqactionsjson servlet"() {
        HttpSecurityCheck check = loadSingleCheck("nc-wMGJvmKd", CHECK_UNDER_TEST)
        CheckExecutionResult result = check createHttpClient(), new ScanContext("http://localhost:" + DEFAULT_PORT + "/")

        Assert.assertEquals 1, result.issues.size()
    }

    @Override
    void setExpectations() {
        mockServerClient().when(
                request()
                        .withMethod("GET")
                        .withPath("/.cqactions.json")
                        .withQueryStringParameters(
                                Parameter.param("authorizableId", "(anonymous|everyone)"),
                                Parameter.optionalParam("predicate", "useradmin"),
                                Parameter.optionalParam("depth", "0"),
                                Parameter.optionalParam("path", "/content"),
                                Parameter.optionalParam("_charset_", "utf8")
                        ))

                .respond(
                        response()
                                .withBody(EXPECTED_RESULT)
                )
    }

    @Override
    void resetExpectations() {
        reset("/.cqactions.json")
    }
}
