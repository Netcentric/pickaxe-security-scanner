/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.checkerdsl.payload

class Generator {

    public static final String DEFAULT_LOWERCASE_ALPHABET = (('a'..'z') + ('0'..'9')).join()

    public static final String LOWERCASE_ALPHABET = (('a'..'z')).join()

    static final int DEFAULT_LENGTH = 9

    static String cacheBuster() {
        cacheBuster(DEFAULT_LOWERCASE_ALPHABET, DEFAULT_LENGTH)
    }

    static String cacheBuster(int length) {
        cacheBuster(DEFAULT_LOWERCASE_ALPHABET, length)
    }

    static String cacheBuster(String utilizedAlphabet, int length) {
        def generator = { String alphabet, int n ->
            new Random().with {
                (1..n).collect { alphabet[nextInt(alphabet.length())] }.join()
            }
        }

        generator(utilizedAlphabet, length)
    }

    static List<String> createUniqueValues(List<String> values, String placeHolder, int cacheBusterLength) {
        String cacheBuster = cacheBuster(cacheBusterLength)
        return values.stream()
                .map { value ->
                    value.replace(placeHolder, cacheBuster)
                }
                .toList()
    }
}
