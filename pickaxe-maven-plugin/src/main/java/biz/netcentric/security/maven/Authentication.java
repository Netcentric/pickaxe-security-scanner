/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.maven;

import biz.netcentric.security.checkerdsl.model.AuthType;
import biz.netcentric.security.checkerdsl.model.AuthenticationConfig;
import org.apache.commons.lang3.StringUtils;
import org.apache.maven.plugins.annotations.Parameter;

public class Authentication {

    @Parameter(property = "authenticationType", defaultValue = "simple")
    private String authenticationType;

    @Parameter
    private String username;

    @Parameter
    private String password;

    @Parameter
    private String token;

    public String getAuthenticationType() {
        return StringUtils.isNotBlank(authenticationType) ? authenticationType : StringUtils.EMPTY;
    }

    public void setAuthenticationType(String authenticationType) {
        this.authenticationType = authenticationType;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    AuthenticationConfig toAuthenticationConfig(){
        AuthenticationConfig authConfig = new AuthenticationConfig();
        String type = getAuthenticationType().toUpperCase();
        if(AuthType.valueOf(type) != null){
            authConfig.setAuthenticationType(AuthType.valueOf(type));
        }
        authConfig.setUsername(this.username);
        authConfig.setPassword(this.password);

        return authConfig;
    }
}
