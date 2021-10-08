/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.payload

class Encoding {

    static String UTF8 = "UTF-8"

    static String toBase64(String value){
        value.bytes.encodeBase64().toString()
    }
}
