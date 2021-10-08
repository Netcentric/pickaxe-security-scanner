/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.dsl.securitycheck

import biz.netcentric.security.checkerdsl.model.Issue

/**
 * Model object representing an entry in a security check run
 */
class HistoryRecord {

    HttpSecurityCheckStep step

    List<Issue> detectedIssues = []

    String getId() {
        step.getId()
    }
}

