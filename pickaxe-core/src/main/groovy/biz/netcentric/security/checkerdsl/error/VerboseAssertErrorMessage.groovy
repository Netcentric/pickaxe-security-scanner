/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.error

class VerboseAssertErrorMessage {

    /**
     * Extension method for String type.
     * Use as follow: assert "The condition must be true" | x==y
     * @param self message itself
     * @param condition condition to check
     * @return initial condition value
     */
    public static Boolean or(String self, Boolean condition) {
        return condition
    }

    public static Boolean or(String self, Object object) {
        if(object instanceof Boolean){
            return object
        }
        return object != null
    }
}
