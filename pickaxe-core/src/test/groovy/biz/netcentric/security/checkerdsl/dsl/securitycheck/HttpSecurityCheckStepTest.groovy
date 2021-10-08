/*
 *
 *  * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *  *
 *  * All rights reserved. This program and the accompanying materials
 *  * are made available under the terms of the Eclipse Public License v1.0
 *  * which accompanies this distribution, and is available at
 *  * http://www.eclipse.org/legal/epl-v10.html
 *
 */
package biz.netcentric.security.checkerdsl.dsl.securitycheck


import org.junit.Assert
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.junit.jupiter.MockitoExtension

@ExtendWith(MockitoExtension.class)
class HttpSecurityCheckStepTest {

    static String BASE_URL = "http://localhost:8080"

    List<String> contentUrlsPaths = ["/content/sites/page1", "/content/sites/page2", "/content/sites/page3", "/content/sites/page4"]

    @Test
    void "url mutations if paths are configured"() {
        List pages = ["/content/sites/article0", "/content/sites/article1", "/content/sites/article2"]
        HttpSecurityCheckStep step = new HttpSecurityCheckStep()
        step.paths(pages)

        def baseUrl = new URL("http://localhost:8080")
        List<URL> mutations = step.createUrlMutations(baseUrl, [])

        pages.each { page ->
            String url  = "http://localhost:8080" + page
            Assert.assertTrue mutations.contains(new URL(url))
        }
    }

    @Test
    void "url mutations if content urls and not paths are configured"() {
        HttpSecurityCheckStep step = new HttpSecurityCheckStep()
        List<URL> contentUrls = []
        contentUrlsPaths.each { path ->
            contentUrls.add new URL("http://localhost:8080" + path)
        }

        List<URL> mutations = step.createUrlMutations(new URL("http://localhost:8080"), contentUrls)

        mutations.eachWithIndex { URL entry, int i ->
            String path = entry.getPath()
        }

        contentUrlsPaths.each { page ->
            URL url = new URL("http://localhost:8080" + page)
            Assert.assertTrue mutations.contains(url)
        }
    }
}
