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

package biz.netcentric.security.checkerdsl.dsl.parser.yaml

/**
 * Scan specification whoch is used to back a YAML scan spec
 */
class ScanSpec {

    String target

    Authentication authentication

    ScanConfig scanConfig

    Reporter reporter
}

class ScanConfig{

    boolean buildinChecks

    boolean runAllChecks

    List<String> loadFrom = []

    List<String> categories = []

    List<String> names = []
}

class Authentication {

    String authenticationType

    String username

    String password

    String token
}

class Reporter{

    List<String> handlers = []

    String outputFolder

}