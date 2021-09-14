package biz.netcentric.security.checkerdsl.dsl

import biz.netcentric.security.checkerdsl.model.ScanContext
import org.junit.Test

import static org.junit.Assert.assertTrue

class ScanDelegateTest {

    @Test
    void testTarget_initializesURLsCorrectly(){
        ScanDelegate delegate = new ScanDelegate()

        def expectedTarget = "http://www.example.com/de.html"
        def expectedContentTargets = ["http://www.example.com/en.html", "http://www.example.com/fr", "http://www.example.com/it/aem"]

        ScanContext context = delegate.target(expectedTarget, expectedContentTargets)

        assertTrue context.getUrl() == (new URL(expectedTarget))
        expectedContentTargets.each {target ->
            assertTrue context.getContentUrls().contains(new URL(target))
        }
    }
}
