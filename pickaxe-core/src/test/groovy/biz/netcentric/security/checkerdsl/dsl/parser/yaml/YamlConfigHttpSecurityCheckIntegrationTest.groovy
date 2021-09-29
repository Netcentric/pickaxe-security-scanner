package biz.netcentric.security.checkerdsl.dsl.parser.yaml

import biz.netcentric.security.checkerdsl.MockServer
import biz.netcentric.security.checkerdsl.config.Spec
import biz.netcentric.security.checkerdsl.config.SpecFormat
import biz.netcentric.security.checkerdsl.dsl.parser.yaml.YamlSpecCheckParser
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.http.AsyncHttpClient
import biz.netcentric.security.checkerdsl.model.ScanContext
import org.junit.Assert
import org.junit.jupiter.api.Test

import static org.mockserver.model.HttpRequest.request
import static org.mockserver.model.HttpResponse.response

class YamlConfigHttpSecurityCheckIntegrationTest extends MockServer {

    String JSON_RESPONSE = '''
    {
        results:12,
        whatever: [1,2,3]
    }
    '''

    private HttpSecurityCheck loadSecurityCheck() {
        String test = prepareYamlTest()
        Spec spec = new Spec(specFormat: SpecFormat.YAML, content: test, location: "no location", name: "yaml check")
        YamlSpecCheckParser parser = new YamlSpecCheckParser()
        List<HttpSecurityCheck> checks = parser.createCheck(spec)
        checks.get(0)
    }

    @Test
    void "single rule is evaluated correctly"() {
        AsyncHttpClient httpClient = new AsyncHttpClient()
        def check = loadSecurityCheck()

        def result = check httpClient, new ScanContext("http://localhost:" + MockServer.DEFAULT_PORT + "/some-irrelevant-base-url.html")

        Assert.assertEquals 2, result.issues.size()
    }

    def prepareYamlTest() {
        def checkDefinition = '''
            id: "yaml-test-1"
            categories:
              - "dispatcher"
              - "checkerdsl"
            vulnerability:
              name: "Data manipulation"
              description: "Upload should not be possible"
              remediation: "Block through AEM dispatcher rules."
              cve: "cwe-2132"
              severity: "HIGH"
            steps:
              - name: "get Data"
                method: "GET"
                paths:
                  - "/crx/de"
                  - "/crx/de/index.jsp"
                extensions:
                  - ".json"
                requestHeaders:
                  host: "example.com"
                  Referer: "referer.example.com"
                authenticationHeaders:
                  authentication: "Basic xyz"
                params:
                  param1: "value1"
                  param2: "value2"
                detect:
                  - type: all
                    expectedStatusCode: 200
                    bodyContains:
                      - "whatever"
                      - "results"
        '''

        checkDefinition
    }

    @Override
    void setExpectations() {
        mockServerClient()
                .when(
                        request()
                                .withPath("/crx/de.json")
                )
                .respond(

                        response(JSON_RESPONSE)
                                .withHeader("content-type", "application/json; charset=utf-8")
                                .withHeader("x-frame-options", "SAMEORIGIN")
                )
    }

    @Override
    void resetExpectations() {
        mockServerClient().reset()
    }
}


