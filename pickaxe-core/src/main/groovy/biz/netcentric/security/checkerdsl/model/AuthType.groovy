/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.model

/**
 * Different supported authentication types
 * SIMPLE: Is using basic authentication where client sends the HTTP Request with no credentials and responds then on the server's challenge
 * PRE_EMPTIVE: Will send the authorization header with initial request
 * TOKEN: Not implemented yet
 */
enum AuthType {
    SIMPLE, PRE_EMPTIVE, TOKEN
}