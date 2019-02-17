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
package org.owasp.dependencycheck.data.lucene;

import javax.annotation.concurrent.NotThreadSafe;
import org.apache.lucene.search.similarities.ClassicSimilarity;

/**
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class DependencySimilarity extends ClassicSimilarity {

    /**
     * <p>
     * Override the default IDF implementation so that frequency within all document is ignored.</p>
     *
     * See <a href="http://www.lucenetutorial.com/advanced-topics/scoring.html">this article</a> for more details.
     *
     * @param docFreq - the number of documents which contain the term
     * @param numDocs - the total number of documents in the collection
     * @return 1
     */
    @Override
    public float idf(long docFreq, long numDocs) {
        return 1;
    }
}
