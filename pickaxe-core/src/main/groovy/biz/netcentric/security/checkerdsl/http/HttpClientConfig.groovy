/*
 *
 *  * (C) Copyright 2020 Netcentric AG.
 *  *
 *  * All rights reserved. This program and the accompanying materials
 *  * are made available under the terms of the Eclipse Public License v1.0
 *  * which accompanies this distribution, and is available at
 *  * http://www.eclipse.org/legal/epl-v10.html
 *
 */

package biz.netcentric.security.checkerdsl.http

import biz.netcentric.security.checkerdsl.model.AuthenticationConfig
import okhttp3.ConnectionPool

import java.util.concurrent.TimeUnit

/**
 * Configuration options for the HttpClient
 */
class HttpClientConfig {

    AuthenticationConfig authenticationConfig

    int connectionPoolSize

    long connectionTimeoutMs

    long readTimeoutMs

    long writeTimeout

    boolean followRedirects

    int threadKeepAliveTime

    boolean cache = false

    TimeUnit keepAliveTimeUnit = TimeUnit.SECONDS

    ConnectionPool createConnectionPool(){
        new ConnectionPool(this.connectionPoolSize, threadKeepAliveTime, keepAliveTimeUnit)
    }
}
