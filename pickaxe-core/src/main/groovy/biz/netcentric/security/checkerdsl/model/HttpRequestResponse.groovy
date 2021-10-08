/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.model

import biz.netcentric.security.checkerdsl.http.method.HttpHeader

/**
 * Represents the complete request and response cycle identified by targetContextDelegate URL.
 *
 * @author thomas.hartmann@netcentric.biz
 * @since 03/2019
 */
class HttpRequestResponse {

    URI uri

    int code

    String body

    String rawRequest

    String rawResponse

    String trimmedResponse

    List<HttpHeader> responseHeaders
}
