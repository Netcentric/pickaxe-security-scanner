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

package biz.netcentric.security.checkerdsl.http.method

class HttpHeader {

    String name

    String value

    String toString(){
        "${name}: ${value}"
    }
}
