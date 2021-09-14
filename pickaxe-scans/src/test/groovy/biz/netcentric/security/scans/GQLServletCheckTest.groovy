package biz.netcentric.security.scans

import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.CheckExecutionResult
import biz.netcentric.security.checkerdsl.model.ScanContext
import org.junit.Assert
import org.junit.jupiter.api.Test
import org.mockserver.model.Parameter

import static org.mockserver.model.HttpRequest.request
import static org.mockserver.model.HttpResponse.response

class GQLServletCheckTest implements MockServerTrait {

    String CHECK_UNDER_TEST = "dispatcher/gql-servlet-check.groovy"

    String EXPECTED_RESULT ='''{"hits":[{"name":"","name_xss":"","_id":"/","_parent":null,"_is_leaf":false,"authorizableId":"everyone","declared":{"modify":{},"replicate":{},"read":{},"create":{},"delete":{},"acl_read":{},"acl_edit":{}},"canreadac":false,"canwriteac":false,"children":["/crx","/content","/bin"]}],"results":1}'''

    @Test
    void "detect GQL servlet"() {
        HttpSecurityCheck check = loadSingleCheck("nc-XjJ15JKp", CHECK_UNDER_TEST)
        CheckExecutionResult result = check createHttpClient(), new ScanContext("http://localhost:" + DEFAULT_PORT + "/")

        Assert.assertEquals 2, result.issues.size()
    }

    @Override
    void setExpectations() {
        mockServerClient().when(
                request()
                        .withMethod("GET")
                        .withPath("/bin/wcm/search/gql.servlet.json")
                        .withQueryStringParameters(
                                Parameter.param("query", "type:base%20limit:..1"),
                                Parameter.param("pathPrefix", "")
                        ))
                .respond(
                        response()
                                .withBody(EXPECTED_RESULT)
                )
    }

    @Override
    void resetExpectations() {
        reset("/bin/wcm/search/gql.servlet.json")
    }
}