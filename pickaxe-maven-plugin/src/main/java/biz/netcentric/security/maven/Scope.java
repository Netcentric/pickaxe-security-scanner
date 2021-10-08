/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package biz.netcentric.security.maven;

import biz.netcentric.security.checkerdsl.dsl.ScanConfiguration;
import org.apache.maven.plugins.annotations.Parameter;

import java.util.Collections;
import java.util.List;

/**
 * Defines the scan scope which configures if all or distinct scan categories are supported
 */
public class Scope {

    @Parameter(defaultValue = "true")
    private boolean runAllChecks;

    @Parameter(property = "categories.category")
    private List<String> categories;

    @Parameter(property = "names.name")
    private List<String> names;

    public boolean isRunAllChecks() {
        return runAllChecks;
    }

    public void setRunAllChecks(boolean runAllChecks) {
        // we can not run all checks if we select specific ones
        if (runAllChecks == true && categories.size() > 0) {
            this.runAllChecks = false;
        }

        if (runAllChecks == true && names.size() > 0) {
            this.runAllChecks = false;
        }

        this.runAllChecks = runAllChecks;
    }

    public List<String> getCategories() {
        return categories != null ? categories : Collections.EMPTY_LIST;
    }

    public void setCategories(List<String> categories) {
        if (categories.size() > 0) {
            this.runAllChecks = false;
        }

        this.categories = categories;
    }

    public List<String> getNames() {
        return names;
    }

    public void setNames(List<String> names) {
        this.names = names;
    }

    public ScanConfiguration toScanConfiguration(){
        ScanConfiguration config = new ScanConfiguration();
        if(this.categories != null && this.categories.size() > 0){
            config.setCategories(this.categories);
        }

        config.setNames(this.names);

        config.setAll(this.isRunAllChecks());

        return config;
    }
}
