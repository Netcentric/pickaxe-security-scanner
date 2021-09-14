package biz.netcentric.security.checkerdsl.config

import org.junit.Assert
import org.junit.jupiter.api.Test

class FilesystemSpecLoaderTest {

    @Test
    void testLoadMultipleConfigsFromLocation() {
        def provider = new FileSystemSpecLoader()

        def resource = this.getClass().getResource('/config-loader-tests/loader')
        def scripts = provider.loadFromLocation(resource.toURI())

        Assert.assertEquals 4, scripts.size()

        scripts.each { script ->
            Assert.assertTrue script.name.contains("-test")
        }
    }

    @Test
    void testLoadSingleFromLocation() {
        def provider = new FileSystemSpecLoader()

        def resource = this.getClass().getResource('/config-loader-tests/loader/simple-test-closure.groovy')
        def scripts = provider.loadFromLocation(resource.toURI())

        Assert.assertEquals 1, scripts.size()
        Assert.assertEquals "simple-test-closure.groovy", scripts.get(0).name
        Assert.assertTrue scripts.get(0).content.contains("CRX Test")
    }
}
