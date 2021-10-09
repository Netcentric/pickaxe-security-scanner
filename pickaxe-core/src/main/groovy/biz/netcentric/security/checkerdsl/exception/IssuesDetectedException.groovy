package biz.netcentric.security.checkerdsl.exception
/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
/**
 * Can be thrown by an the scan engine or a consumer if it is desired to stop further processing due to detected issues.
 */
class IssuesDetectedException extends RuntimeException {

    IssuesDetectedException() {
        super()
    }

    IssuesDetectedException(String message) {
        super(message)
    }
}
