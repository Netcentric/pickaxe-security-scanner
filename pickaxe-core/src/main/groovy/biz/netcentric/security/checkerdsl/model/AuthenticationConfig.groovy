/*
 * (C) Copyright 2020 Netcentric AG.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.model

/**
 * Authentication configuration which can be used to define up a scan's authentication requirements.
 */
class AuthenticationConfig {

    AuthType authenticationType = AuthType.SIMPLE

    String username

    String password

    String token

    def authenticationType(AuthType authType) {
        this.authenticationType = authType
    }

    def authType(AuthType authType) {
        this.authenticationType = authType
    }

    def username(String username) {
        this.username = username
    }

    def password(String password) {
        this.password = password
    }

    def token(String token) {
        this.token = token
    }
}
