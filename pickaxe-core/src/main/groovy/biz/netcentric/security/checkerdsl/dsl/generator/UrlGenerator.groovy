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

package biz.netcentric.security.checkerdsl.dsl.generator

import biz.netcentric.security.checkerdsl.payload.FilterEvasion
import groovy.util.logging.Slf4j
import org.apache.commons.lang3.StringUtils

/**
 * Generates a set of unique Urls based on the internal state of the Generator.
 * All members of the Generator are considered. Unset instance variables are ignored.
 *
 * Settings the path is mandatory, else the list will be empty.
 *
 */
@Slf4j
class UrlGenerator {

    public static final String DOT = "."

    public static final String SLASH = "/"

    List<String> selectors

    List<String> extensions

    List<String> suffixes

    List<String> bypasses

    boolean mutateSlash

    Set<String> generate(Collection<String> paths) {
        boolean hasPaths = isNotNullOrEmpty(paths)
        boolean hasSelectors = isNotNullOrEmpty(selectors)
        boolean hasExtensions = isNotNullOrEmpty(extensions)
        boolean hasSuffixes = isNotNullOrEmpty(suffixes)
        boolean hasBypasses = isNotNullOrEmpty(bypasses)

        // avoid duplicates but keep the insert order
        Set<String> mutations = new LinkedHashSet<>()
        if (hasPaths) {

            mutations.addAll paths.flatten()

            // selectors can only be there if there are also extensions.
            if (hasExtensions && hasSelectors) {
                mutations = this.generatePrefixedURIElements(mutations, selectors, DOT)
            } else if(hasSelectors) {
                log.warn("Selectors should not be used without extensions. Skipping selectors in UriGenerator.")
            }

            if (hasExtensions) {
                mutations = this.generateURIElements(mutations, extensions)
            }

            if (hasExtensions && hasSuffixes) {
                mutations = this.generatePrefixedURIElements(mutations, suffixes, SLASH)
            } else if(hasSuffixes) {
                log.warn("Suffixes should not be used without extensions. Skipping suffixes in UriGenerator.")
            }

            if (hasBypasses) {
                mutations = this.generateURIElements(mutations, bypasses)
            }

            // TODO: mutateSlash is not currently used by any checks, we shoulds see when it makes sense to use it
            if (Boolean.valueOf(mutateSlash)) {
                FilterEvasion.PATH_DISPATCHER_BYPASS.getAsList().flatten().each { pathMutation ->
                        mutations.each {
                            mutation ->
                                mutations = mutations.collect { it.replaceAll("/", mutation) }
                        }
                }
            }

            log.debug("Created {} url mutations", mutations.size())
        }

        mutations
    }

    private boolean isNotNullOrEmpty(List<String> listValue) {
        listValue != null && !listValue.isEmpty()
    }

    private Set<String> generateURIElements(Set<String> elements, Collection<String> modifiers) {
        def tempModifiers = []
        elements.each { element ->
            modifiers.collect(tempModifiers) { element + it }
        }

        tempModifiers
    }

    private Set<String> generatePrefixedURIElements(Set<String> elements, Collection<String> modifiers, String prefix) {
        def tempModifiers = []
        elements.each { element ->
            modifiers.collect(tempModifiers) { modifier ->
                if(StringUtils.isNotEmpty(modifier)){
                    String prefixedModifier = modifier.startsWith(prefix) ? modifier : prefix + modifier
                    element + prefixedModifier
                }else{
                    element
                }
            }
        }

        tempModifiers
    }
}
