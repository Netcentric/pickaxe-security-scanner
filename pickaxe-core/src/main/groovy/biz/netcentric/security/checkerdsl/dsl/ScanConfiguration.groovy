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
package biz.netcentric.security.checkerdsl.dsl

import biz.netcentric.security.checkerdsl.http.HttpClientConfig
import biz.netcentric.security.checkerdsl.model.AuthenticationConfig

/**
 * Defines a ScanConfiguration which set's the boundary parameters for the actual scan execution.
 */
class ScanConfiguration {

    AuthenticationConfig authConfig

    int connectionPoolSize = 10

    long connectionTimeoutMs = 10000

    long readTimeoutMs = 10000

    long writeTimeoutMs = 10000

    boolean followRedirects = false

    int threadKeepAliveSeconds = 10

    int checkThrottlingMillis = 0

    List<String> ignored = []

    List<String> falsePositives = []

    List<String> categories = []

    List<String> names = []

    boolean all = false

    def authentication(@DelegatesTo(strategy = Closure.OWNER_FIRST, value = AuthenticationConfig) Closure closure) {
        if (closure != null) {
            AuthenticationConfig authenticationConfig = new AuthenticationConfig()
            closure.setDelegate(authenticationConfig)
            closure.setResolveStrategy(Closure.OWNER_FIRST)

            closure()
            this.authConfig = authenticationConfig
        }
    }

    def authentication(AuthenticationConfig authenticationConfig) {
        this.authConfig = authenticationConfig
    }

    HttpClientConfig createHttpClientConfig() {
        new HttpClientConfig(
                authenticationConfig: this.authConfig,
                connectionPoolSize: this.connectionPoolSize,
                connectionTimeoutMs: this.connectionTimeoutMs,
                readTimeoutMs: this.readTimeoutMs,
                writeTimeout: this.writeTimeoutMs,
                followRedirects: this.followRedirects,
                threadKeepAliveTime: this.threadKeepAliveSeconds)
    }

    def categories(List<String> categories) {
        this.categories.addAll categories
    }

    def category(String category) {
        this.categories << category
    }

    def categories(String... categories) {
        this.categories.addAll categories
    }

    def ignore(String checkId) {
        this.ignored << checkId
    }

    def ignored(String... checkIds) {
        this.ignored.addAll checkIds
    }

    def ignored(List<String> checkIds) {
        this.ignored.addAll checkIds
    }

    def falsePositives(String... checkIds) {
        this.falsePositives.addAll checkIds
    }

    def falsePositives(List<String> checkIds) {
        this.falsePositives.addAll checkIds
    }

    def falsePositive(String checkId) {
        this.falsePositives << checkId
    }

    def names(List<String> names) {
        this.names.addAll names
    }

    def names(String... names) {
        this.names.addAll names
    }

    def name(String name) {
        this.names << name
    }

    def connectionPoolSize(int connectionPoolSize) {
        this.connectionPoolSize = connectionPoolSize
    }

    def checkThrottlingMillis(long checkThrottlingMillis){
        this.checkThrottlingMillis = checkThrottlingMillis
    }

    def runAllChecks(boolean runAll) {
        this.all = runAll
    }

    def selected() {
        this.all = false
    }

    AuthenticationConfig getAuthenticationConfig() {
        return authConfig
    }

    static ScanConfiguration create(@DelegatesTo(strategy = Closure.DELEGATE_FIRST, value = ScanConfiguration) Closure script) {
        def scanConfiguration = new ScanConfiguration()
        script.resolveStrategy = Closure.DELEGATE_ONLY
        script.delegate = scanConfiguration
        script()
        return scanConfiguration
    }

    String toString() {
        return "ScanConfiguration{" +
                "authConfig=" + authConfig +
                ", ignored=" + ignored +
                ", falsePositives=" + falsePositives +
                ", categories=" + categories +
                ", names=" + names +
                ", all=" + all +
                '}';
    }
}




