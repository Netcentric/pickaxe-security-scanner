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
package biz.netcentric.security.checkerdsl.commandlinetools

import com.aventrix.jnanoid.jnanoid.NanoIdUtils
import groovy.util.logging.Slf4j

/**
 * Generates a random ID which can be used to register a check.
 * Tools i mainly for convenience when writing a new security check.
 */
@Slf4j
class CheckIDGenerator {

    static int SIZE = 8

    static char[] DEFAULT_PREFIX = "AEM-SEC-CHECK-"

    static char[] DEFAULT_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-".toCharArray()

    String createUniqueId() {
        Random random = new Random();
        NanoIdUtils.randomNanoId(random, DEFAULT_ALPHABET, SIZE); // "AEM-SEC-CHECK-babbcaab"
    }
}
