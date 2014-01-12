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
package org.owasp.dependencycheck.data.lucene;

import org.apache.lucene.search.similarities.DefaultSimilarity;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DependencySimilarity extends DefaultSimilarity {

    /**
     * the serial version uid.
     */
    private static final long serialVersionUID = 1L;

    /**
     * <p>Override the default idf implementation so that frequency within all
     * document is ignored.</p>
     *
     * See <a
     * href="http://www.lucenetutorial.com/advanced-topics/scoring.html">this
     * article</a> for more details.
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
