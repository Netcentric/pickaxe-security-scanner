package biz.netcentric.security.scans

import biz.netcentric.security.checkerdsl.dsl.SecurityCheckProvider
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.http.AsyncHttpClient
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.mockserver.client.MockServerClient
import org.mockserver.integration.ClientAndServer

import static org.mockserver.integration.ClientAndServer.startClientAndServer
import static org.mockserver.model.HttpRequest.request

trait MockServerTrait {

    static int DEFAULT_PORT = 39999

    private static ClientAndServer mockServer

    @BeforeAll
    static void startServer() {
        mockServer = startClientAndServer(DEFAULT_PORT)
    }

    @AfterAll
    static void stopServer() {
        mockServer.stop()
    }

    @BeforeEach
    void initialize() {
        setExpectations()
    }

    @AfterEach
    void clean() {
        resetExpectations()
    }

    abstract void setExpectations();

    abstract void resetExpectations();

    void resetAll() {
        mockServerClient().reset()
    }

    void reset(String path) {
        mockServerClient().clear(request().withPath(path))
    }

    MockServerClient mockServerClient() {
        new MockServerClient("localhost", DEFAULT_PORT)
    }

    SecurityCheckProvider initCheckProvider(String... paths) {
        SecurityCheckProvider securityCheckProvider = new SecurityCheckProvider()
        paths.each {
            def resource = getClass().getClassLoader().getResource(it)
            securityCheckProvider.initializeCheckFromFileSystem(resource.toURI())
        }
        securityCheckProvider
    }


    HttpSecurityCheck loadSingleCheck(String name, String path) {
        SecurityCheckProvider provider = initCheckProvider(path)
        return provider.checkClosures.get(name).get(0)
    }

    AsyncHttpClient createHttpClient(){
        AsyncHttpClient httpClient = new AsyncHttpClient()

        httpClient
    }
}
