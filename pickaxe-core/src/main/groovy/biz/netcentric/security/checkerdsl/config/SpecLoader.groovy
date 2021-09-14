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
package biz.netcentric.security.checkerdsl.config

/**
 * The SpecLoader is supposed to retrieve one or multiple specs from a defined location and loads it into a list of
 */
trait SpecLoader {

    final String GROOVY_EXTENSION = ".groovy"

    final String[] YAML_EXTENSIONS = [".yaml", ".yml"]

    abstract List<Spec> loadFromLocation(URI uri)

    abstract List<Spec> loadFromLocation(URL resource)

    abstract List<Spec> loadFromLocation(String location)

    void addIfMatchingScript(List<Spec> scripts, File file){
        if (isGroovyFile(file)) {
            scripts << new Spec([specFormat: SpecFormat.GROOVY, content: file.text, location: file.absolutePath, name: file.name])
        }else if(isYamlFile(file)){
            scripts << new Spec([specFormat: SpecFormat.YAML, content: file.text, location: file.absolutePath, name: file.name])
        }
    }

    def isGroovyFile(File file) {
        file.name.endsWith(GROOVY_EXTENSION)
    }

    def isYamlFile(File file) {
        file.name.endsWithAny(YAML_EXTENSIONS)
    }
}