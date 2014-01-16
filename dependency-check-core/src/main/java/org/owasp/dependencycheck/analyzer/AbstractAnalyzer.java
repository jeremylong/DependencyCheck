/*
 * This file is part of dependency-check-core.
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
     * Utility method to help in the creation of the extensions set. This constructs a new Set that can be used in a
     * final static declaration.<br/><br/>
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
