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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cpe;

import java.io.IOException;
import java.util.Set;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.TopDocs;
import org.owasp.dependencycheck.utils.Pair;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long
 */
public interface MemoryIndex extends AutoCloseable {

    /**
     * Retrieves a document from the Index.
     *
     * @param documentId the id of the document to retrieve
     * @return the Document
     * @throws IOException thrown if there is an IOException
     */
    Document getDocument(int documentId) throws IOException;

    /**
     * Creates and loads data into an in memory index.
     *
     * @param data the CPE data
     * @param settings a reference to the dependency-check settings
     * @throws IndexException thrown if there is an error creating the index
     */
    void open(Set<Pair<String, String>> data, Settings settings) throws IndexException;

    /**
     * Parses the given string into a Lucene Query.
     *
     * @param searchString the search text
     * @return the Query object
     * @throws ParseException thrown if the search text cannot be parsed
     * @throws IndexException thrown if there is an error resetting the
     * analyzers
     */
    Query parseQuery(String searchString) throws ParseException, IndexException;

    /**
     * Searches the index using the given search string.
     *
     * @param searchString the query text
     * @param maxQueryResults the maximum number of documents to return
     * @return the TopDocs found by the search
     * @throws ParseException thrown when the searchString is invalid
     * @throws IndexException thrown when there is an internal error resetting
     * the search analyzer
     * @throws IOException is thrown if there is an issue with the underlying
     * Index
     */
    TopDocs search(String searchString, int maxQueryResults) throws ParseException, IndexException, IOException;

    /**
     * Searches the index using the given query.
     *
     * @param query the query used to search the index
     * @param maxQueryResults the max number of results to return
     * @return the TopDocs found be the query
     * @throws CorruptIndexException thrown if the Index is corrupt
     * @throws IOException thrown if there is an IOException
     */
    TopDocs search(Query query, int maxQueryResults) throws CorruptIndexException, IOException;

    /**
     * Closes the MemoryIndex.
     */
    @Override
    void close();
}
