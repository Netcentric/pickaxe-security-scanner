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

package biz.netcentric.security.checkerdsl.dsl.generator

import org.apache.commons.lang3.StringUtils
import org.junit.Assert
import org.junit.jupiter.api.Test

class UrlGeneratorTest {

    static List<String> PATHS = ["/content/example/path1", "/content/example/path2", "/content/example/path3", "/content/example/path4", "/content/example/path5"]

    static List<String> EXTENSIONS = [".json", ".html", ".xml"]

    static List<String> SELECTORS = [".social", ".inbox", "0.0", ""]

    static List<String> SUFFIXES = ["/suffix", "/suffix/additional/suffix", "", "suffixWithoutASlash/de/en"]

    static List<String> BYPASSES = ["", ".json", ";%0a{0}.html", ".0.html", "/0.html"]

    @Test
    void "paths are generated"() {
        UrlGenerator generator = new UrlGenerator()
        Set<String> mutatedUris = generator.generate(PATHS)

        assertCollectionsAreEqual(PATHS, mutatedUris)
    }

    @Test
    void "paths are generated without duplicates"() {
        List<String> paths = PATHS.clone()
        paths.add("/content/example/path1")

        UrlGenerator generator = new UrlGenerator()
        Set<String> mutatedUris = generator.generate(paths)

        assertCollectionsAreEqual(PATHS, mutatedUris)
    }


    @Test
    void "paths and extensions are generated"() {
        UrlGenerator generator = new UrlGenerator(extensions: EXTENSIONS)
        Set<String> mutatedUris = generator.generate(PATHS)

        List<String> expectedPaths = []
        PATHS.each { path ->
            EXTENSIONS.each { extension ->
                expectedPaths.add path + extension
            }
        }

        assertCollectionsAreEqual(expectedPaths, mutatedUris)
    }

    @Test
    void "paths and selectors and extensions with suffixes are generated"() {
        UrlGenerator generator = new UrlGenerator(extensions: EXTENSIONS, selectors: SELECTORS, suffixes: SUFFIXES)
        Set<String> mutatedUris = generator.generate(PATHS)

        Set<String> expectedPaths = new HashSet<>()
        PATHS.each { path ->
            SELECTORS.each { selector ->
                if (StringUtils.isNotEmpty(selector)) {
                    String dotPrefixedSelector = selector.startsWith(".") ? selector : "." + selector
                    EXTENSIONS.each { extension ->
                        expectedPaths.add path + dotPrefixedSelector + extension
                    }
                } else {
                    EXTENSIONS.each { extension ->
                        expectedPaths.add path + extension
                    }
                }
            }
        }

        Set<String> suffixedPaths = new HashSet<>()
        expectedPaths.each { path ->
            SUFFIXES.collect { suffix ->
                if (StringUtils.isNotEmpty(suffix)) {
                    String dotPrefixedSuffix = suffix.startsWith("/") ? suffix : "/" + suffix
                    suffixedPaths.add path + dotPrefixedSuffix
                } else {
                    suffixedPaths.add path
                }
            }
        }

        assertCollectionsAreEqual(suffixedPaths, mutatedUris)
    }

    @Test
    void "no selectors to paths when extensions are missing"() {
        UrlGenerator generator = new UrlGenerator(extensions: [], selectors: SELECTORS)
        Set<String> mutatedUris = generator.generate(PATHS)

        assertCollectionsAreEqual(PATHS, mutatedUris)
    }

    @Test
    void "paths and selectors and extensions are generated"() {
        UrlGenerator generator = new UrlGenerator(extensions: EXTENSIONS, selectors: SELECTORS)
        Set<String> mutatedUris = generator.generate(PATHS)

        Set<String> expectedPaths = new HashSet<>()
        PATHS.each { path ->
            SELECTORS.each { selector ->
                if (StringUtils.isNotEmpty(selector)) {
                    String dotPrefixedSelector = selector.startsWith(".") ? selector : "." + selector
                    EXTENSIONS.each { extension ->
                        expectedPaths.add path + dotPrefixedSelector + extension
                    }
                } else {
                    EXTENSIONS.each { extension ->
                        expectedPaths.add path + extension
                    }
                }
            }
        }

        assertCollectionsAreEqual(expectedPaths, mutatedUris)
    }

    @Test
    void "paths and extensions and bypasses are generated"() {
        UrlGenerator generator = new UrlGenerator(extensions: EXTENSIONS, bypasses: BYPASSES)
        Set<String> mutatedUris = generator.generate(PATHS)

        Set<String> expectedPaths = new LinkedHashSet()
        PATHS.each { path ->
            EXTENSIONS.each { extension ->
                BYPASSES.each { bypass ->
                    expectedPaths.add path + extension + bypass
                }
            }
        }

        assertCollectionsAreEqual(expectedPaths, mutatedUris)
    }

    @Test
    void "no suffices are used when extensions are missing"() {
        UrlGenerator generator = new UrlGenerator(extensions: [], suffixes: SUFFIXES)
        Set<String> mutatedUris = generator.generate(PATHS)

        assertCollectionsAreEqual(PATHS, mutatedUris)
    }

    private void assertCollectionsAreEqual(Collection<String> expected, Collection<String> toCompare) {
        Assert.assertEquals(expected.size(), toCompare.size())
        expected.each { path ->
            Assert.assertTrue toCompare.contains(path)
        }
    }
}
