/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.report.data

/**
 * Value object representing a reportable check entity.
 */
class SecurityCheckReportEntity {

    String id

    String name

    String cve

    String vulnerabilityName

    String vulnerabilityDescription

    String suggestedMitigation

    int numberOfFindings

    String toExtendedName() {
        "Check Name: $name Internal Check ID: $id - CVE: $cve"
    }
}
