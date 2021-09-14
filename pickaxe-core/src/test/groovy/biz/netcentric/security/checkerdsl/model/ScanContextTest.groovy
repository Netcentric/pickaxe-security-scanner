package biz.netcentric.security.checkerdsl.model

import org.junit.Assert
import org.junit.jupiter.api.Test

import static org.junit.Assert.assertTrue

class ScanContextTest {

    def expectedTarget = "http://www.example.com/de.html"
    def contentTargets = ["/en.html", "http://www.example.com/fr", "http://www.example.com/it/aem", "some/weird/path.png"]
    def expectedContentTargets = ["http://www.example.com/en.html", "http://www.example.com/fr", "http://www.example.com/it/aem", "http://www.example.com/some/weird/path.png"]

    @Test
    void createContext(){
        ScanContext context = new ScanContext(expectedTarget)
        Assert.assertEquals new URL(expectedTarget), context.getUrl()
    }

    @Test
    void createContextWithMultipleUrls(){
        ScanContext context = new ScanContext(expectedTarget, contentTargets)

        Assert.assertEquals new URL(expectedTarget), context.getUrl()
        expectedContentTargets.each {target ->
            assertTrue context.getContentUrls().contains(new URL(target))
        }
    }
}
