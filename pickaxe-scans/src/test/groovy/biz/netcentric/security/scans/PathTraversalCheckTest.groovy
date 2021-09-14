package biz.netcentric.security.scans

import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.CheckExecutionResult
import biz.netcentric.security.checkerdsl.model.ScanContext
import org.junit.Assert
import org.junit.jupiter.api.Test

import static org.mockserver.model.HttpRequest.request
import static org.mockserver.model.HttpResponse.response

class PathTraversalCheckTest implements MockServerTrait {

    String CHECK_UNDER_TEST = "dispatcher/jetty-path-traversal-bypass.groovy"

    String EXPECTED_RESULT = '''[{"id":"crx","uri":"/crx","jcr:primaryType":"nt:unstructured"},{"id":"content","uri":"/content","jcr:primaryType":"sling:OrderedFolder","jcr:mixinTypes":["rep:AccessControllable"],"jcr:createdBy":"admin","jcr:created":"2018-07-17T09:01:24.441+02:00"},{"id":"bin","uri":"/bin","jcr:primaryType":"nt:folder","jcr:mixinTypes":["mix:versionable"],"jcr:createdBy":"admin","jcr:versionHistory":"b5119421-9f53-462b-ae0a-4de557ee64c1","jcr:predecessors":[],"jcr:created":"2018-07-17T09:01:35.232+02:00","jcr:baseVersion":"cbb1fc16-1a4f-4de7-a80a-60b65a1ebb4e","jcr:isCheckedOut":false,"jcr:uuid":"40ed38c9-cb13-41dc-8602-0249e2c1b4c2"}]'''

    @Test
    void "find path traversal issue"() {
        HttpSecurityCheck check = loadSingleCheck("nc-Ow57Pirox", CHECK_UNDER_TEST)
        CheckExecutionResult result = check createHttpClient(), new ScanContext("http://localhost:" + DEFAULT_PORT + "/de.html")

        Assert.assertTrue result.hasFindings()
    }

    @Override
    void setExpectations() {
        mockServerClient().when(
                request()
                        .withMethod("GET")
                        .withPath("/de/..;/.children.json/a.txt"))
                        .respond(
                                response()
                                        .withBody(EXPECTED_RESULT)
                        )
    }

    @Override
    void resetExpectations() {
        reset("/de/..;/.children.json/a.txt")
    }
}