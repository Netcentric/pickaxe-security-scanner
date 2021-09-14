/*
 * (C) Copyright 2020 Netcentric AG.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.model

import org.apache.commons.lang3.StringUtils

/**
 * Context of the actual scan operation which identifies the targetContextDelegate.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 03/2019
 */
class ScanContext {

    URL url

    List<URL> contentUrls = []

    ScanContext(String url) {
        this.url = new URL(url)
    }

    ScanContext(String url, List<String> contentUrlsToAdd) {
        this.url = new URL(url)
        this.contentUrls = contentUrlsToAdd.stream()
                .map { contentUrl ->
                    URL target = StringUtils.startsWithAny(contentUrl, "http", "https") ? new URL(contentUrl) : create(contentUrl)
                    target
                }
                .toList()
    }

    void initialize() {
        // makes sure we have the current URL as a target.
        // This method is supposed to be called by before scan execution
        this.contentUrls.add(0, this.url)
    }

    URI toUri() {
        url.toURI()
    }

    URL create(def path) {
        String prefixedPath = StringUtils.startsWith(path, "/") ? path : "/${path}"
        new URL(url.protocol, url.host, url.port, prefixedPath)
    }

    URL createTarget(def path, def query) {
        def file = path + "?" + query
        new URL(url.protocol, url.host, url.port, file)
    }
}
