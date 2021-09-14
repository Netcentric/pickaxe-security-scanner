package biz.netcentric.security.checkerdsl

import biz.netcentric.security.checkerdsl.dsl.SecurityCheckProvider
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.mockserver.client.MockServerClient
import org.mockserver.integration.ClientAndServer

abstract class MockServer {

    static int DEFAULT_PORT = 39999

    private static ClientAndServer mockServer

    @BeforeAll
    static void startServer() {
        mockServer = org.mockserver.integration.ClientAndServer.startClientAndServer(DEFAULT_PORT)
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
        mockServerClient().clear(org.mockserver.model.HttpRequest.request().withPath(path))
    }

    MockServerClient mockServerClient() {
        new MockServerClient("localhost", DEFAULT_PORT)
    }

    SecurityCheckProvider initCheckProvider(String... paths) {
        SecurityCheckProvider securityCheckProvider = new SecurityCheckProvider()
        paths.each {
            def resource = this.getClass().getResource(it)
            securityCheckProvider.initializeCheckFromFileSystem(resource.toURI())
        }
        securityCheckProvider
    }


    HttpSecurityCheck loadSingleCheck(String name, String path) {
        SecurityCheckProvider provider = initCheckProvider(path)
        return provider.checkClosures.get(name).get(0)
    }
}
