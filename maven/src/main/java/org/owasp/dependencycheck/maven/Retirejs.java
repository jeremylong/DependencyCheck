/*
 * This file is part of dependency-check-maven.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.maven;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * Simple POJO for Maven configuration.
 *
 * @author Jeremy Long
 */
public class Retirejs {

    /**
     * The retire JS content filters.
     */
    private String[] filters;
    /**
     * Whether or not retire JS should filter non-vulnerable jar files from the
     * report.
     */
    private Boolean filterNonVulnerable;

    /**
     * Returns the retire JS content filters.
     *
     * @return the retire JS content filters
     */
    @SuppressFBWarnings(justification = "use case for configuration object - these warnings are okay",
            value = {"EI_EXPOSE_REP", "UWF_UNWRITTEN_FIELD"})
    public String[] getFilters() {
        return filters;
    }

    /**
     * Returns whether or not retire JS should remove non-vulnerable JS files
     * from the report.
     *
     * @return whether or not retire JS should remove non-vulnerable JS files
     * from the report
     */
    @SuppressFBWarnings(justification = "use case for configuration object - the warning is okay",
            value = {"UWF_UNWRITTEN_FIELD"})
    public Boolean getFilterNonVulnerable() {
        return filterNonVulnerable;
    }
}
