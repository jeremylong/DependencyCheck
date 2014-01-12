/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public abstract class AbstractAnalyzer implements Analyzer {

    /**
     * Utility method to help in the creation of the extensions set. This
     * constructs a new Set that can be used in a final static
     * declaration.<br/><br/>
     *
     * This implementation was copied from
     * http://stackoverflow.com/questions/2041778/initialize-java-hashset-values-by-construction
     *
     * @param strings a list of strings to add to the set.
     * @return a Set of strings.
     */
    protected static Set<String> newHashSet(String... strings) {
        final Set<String> set = new HashSet<String>();

        Collections.addAll(set, strings);
        return set;
    }

    /**
     * The initialize method does nothing for this Analyzer.
     *
     * @throws Exception thrown if there is an exception
     */
    @Override
    public void initialize() throws Exception {
        //do nothing
    }

    /**
     * The close method does nothing for this Analyzer.
     *
     * @throws Exception thrown if there is an exception
     */
    @Override
    public void close() throws Exception {
        //do nothing
    }
}
