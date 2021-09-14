package biz.netcentric.security.checkerdsl.dsl

import org.junit.Assert
import org.junit.Test

class SecurityCheckProviderTest {

    static final String TEST_FILE = "/config-loader-tests/config/SecurityCheckProviderTest-Spec.groovy"

    static final String TEST_FILE2 = "/config-loader-tests/config/SecurityCheckProviderTest-Spec2.groovy"

    static final String TEST_FILE_WITHOUT_IMPORTS = "/config-loader-tests/config/SecurityCheckProviderTest-WithoutImports.groovy"

    static final String TEST_YAML_SPEC = "/config-loader-tests/config/SecurityCheckProviderTest-YamlSpec1.yaml"

    @Test
    void testInitializeFromFileSystemSuccessfully(){
        SecurityCheckProvider securityCheckProvider = initClosureMap(TEST_FILE, TEST_YAML_SPEC)

        Assert.assertTrue securityCheckProvider.checkClosures.containsKey("test-1")
        Assert.assertTrue securityCheckProvider.checkClosures.containsKey("yaml-test-1")
    }

    private SecurityCheckProvider initClosureMap(String... paths) {
        SecurityCheckProvider securityCheckProvider = new SecurityCheckProvider()
        for(String path : paths){
            URL resource = this.getClass().getResource(path)
            securityCheckProvider.initializeCheckFromFileSystem(resource)
        }

        securityCheckProvider
    }

    @Test
    void "get a specific test by selected category"(){
        SecurityCheckProvider securityCheckProvider = initClosureMap(TEST_FILE, TEST_FILE2)

        Assert.assertTrue securityCheckProvider.checkClosures.size() == 2

        def checks = securityCheckProvider.getByCategory(["dispatcher"])
        Assert.assertEquals "test-2", checks.get(0).id
    }

    @Test
    void "get multiple specific tests by selected category"(){
        SecurityCheckProvider securityCheckProvider = initClosureMap(TEST_FILE, TEST_FILE2)

        Assert.assertTrue securityCheckProvider.checkClosures.size() == 2

        def checks = securityCheckProvider.getByCategory(["checkerdsl"])

        List expectedIds = ["test-1", "test-2"]
        checks.each {check ->
            Assert.assertNotNull expectedIds.find{it -> check.id}
        }
    }

    @Test
    void "load a script without declared imports"(){
        SecurityCheckProvider securityCheckProvider = initClosureMap(TEST_FILE_WITHOUT_IMPORTS)

        Assert.assertTrue securityCheckProvider.checkClosures.size() == 1

        def checks = securityCheckProvider.getByCategory(["checkerdsl"])

        Assert.assertEquals "test-3", checks.get(0).id
    }
}
