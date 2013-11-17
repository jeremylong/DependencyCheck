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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cpe;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.core.KeywordAnalyzer;
import org.apache.lucene.analysis.miscellaneous.PerFieldAnalyzerWrapper;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.util.Version;
import org.owasp.dependencycheck.data.lucene.FieldAnalyzer;
import org.owasp.dependencycheck.data.lucene.LuceneUtils;
import org.owasp.dependencycheck.data.lucene.SearchFieldAnalyzer;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class CpeIndexReader extends BaseIndex {

    /**
     * The Lucene IndexReader.
     */
    private IndexReader indexReader;
    /**
     * The Lucene IndexSearcher.
     */
    private IndexSearcher indexSearcher;
    /**
     * The Lucene Analyzer used for Searching.
     */
    private Analyzer searchingAnalyzer;
    /**
     * The Lucene QueryParser used for Searching.
     */
    private QueryParser queryParser;
    /**
     * The search field analyzer for the product field.
     */
    private SearchFieldAnalyzer productSearchFieldAnalyzer;
    /**
     * The search field analyzer for the vendor field.
     */
    private SearchFieldAnalyzer vendorSearchFieldAnalyzer;

    /**
     * Opens the CPE Index.
     *
     * @throws IOException is thrown if an IOException occurs opening the index.
     */
    @Override
    public void open() throws IOException {
        super.open();
        indexReader = DirectoryReader.open(getDirectory());
        indexSearcher = new IndexSearcher(indexReader);
        searchingAnalyzer = createSearchingAnalyzer();
        queryParser = new QueryParser(LuceneUtils.CURRENT_VERSION, Fields.DOCUMENT_KEY, searchingAnalyzer);
    }

    /**
     * Closes the CPE Index.
     */
    @Override
    public void close() {
        //TODO remove spinlock (shared)
        if (searchingAnalyzer != null) {
            searchingAnalyzer.close();
            searchingAnalyzer = null;
        }
        if (indexReader != null) {
            try {
                indexReader.close();
            } catch (IOException ex) {
                Logger.getLogger(CpeIndexReader.class.getName()).log(Level.FINEST, null, ex);
            }
            indexReader = null;
        }
        queryParser = null;
        indexSearcher = null;
        super.close();
    }

    /**
     * Searches the index using the given search string.
     *
     * @param searchString the query text
     * @param maxQueryResults the maximum number of documents to return
     * @return the TopDocs found by the search
     * @throws ParseException thrown when the searchString is invalid
     * @throws IOException is thrown if there is an issue with the underlying
     * Index
     */
    public TopDocs search(String searchString, int maxQueryResults) throws ParseException, IOException {
        if (searchString == null || searchString.trim().isEmpty()) {
            throw new ParseException("Query is null or empty");
        }
        if (queryParser == null) {
            if (isOpen()) {
                final String msg = String.format("QueryParser is null for query: '%s'. Attempting to reopen index.",
                        searchString);
                Logger.getLogger(CpeIndexReader.class.getName()).log(Level.WARNING, msg);
                close();
                open();
            } else {
                final String msg = String.format("QueryParser is null, but data source is open, for query: '%s'. Attempting to reopen index.",
                        searchString);
                Logger.getLogger(CpeIndexReader.class.getName()).log(Level.WARNING, msg);
                close();
                open();
            }
        }
        final Query query = queryParser.parse(searchString);
        return indexSearcher.search(query, maxQueryResults);
    }

    /**
     * Searches the index using the given query.
     *
     * @param query the query used to search the index
     * @param maxQueryResults the max number of results to return
     * @return the TopDocs found be the query
     * @throws CorruptIndexException thrown if the Index is corrupt
     * @throws IOException thrown if there is an IOException
     */
    public TopDocs search(Query query, int maxQueryResults) throws CorruptIndexException, IOException {
        resetSearchingAnalyzer();
        return indexSearcher.search(query, maxQueryResults);
    }

    /**
     * Retrieves a document from the Index.
     *
     * @param documentId the id of the document to retrieve
     * @return the Document
     * @throws IOException thrown if there is an IOException
     */
    public Document getDocument(int documentId) throws IOException {
        return indexSearcher.doc(documentId);
    }

    /**
     * Creates an Analyzer for searching the CPE Index.
     *
     * @return the CPE Analyzer.
     */
    @SuppressWarnings("unchecked")
    private Analyzer createSearchingAnalyzer() {
        final Map fieldAnalyzers = new HashMap();
        fieldAnalyzers.put(Fields.DOCUMENT_KEY, new KeywordAnalyzer());
        productSearchFieldAnalyzer = new SearchFieldAnalyzer(LuceneUtils.CURRENT_VERSION);
        vendorSearchFieldAnalyzer = new SearchFieldAnalyzer(LuceneUtils.CURRENT_VERSION);
        fieldAnalyzers.put(Fields.PRODUCT, productSearchFieldAnalyzer);
        fieldAnalyzers.put(Fields.VENDOR, vendorSearchFieldAnalyzer);

        return new PerFieldAnalyzerWrapper(new FieldAnalyzer(LuceneUtils.CURRENT_VERSION), fieldAnalyzers);
    }

    /**
     * Resets the searching analyzers
     */
    private void resetSearchingAnalyzer() {
        if (productSearchFieldAnalyzer != null) {
            productSearchFieldAnalyzer.clear();
        }
        if (vendorSearchFieldAnalyzer != null) {
            vendorSearchFieldAnalyzer.clear();
        }
    }

    /**
     * Returns the number of CPE entries stored in the index.
     *
     * @return the number of CPE entries stored in the index
     */
    public int numDocs() {
        if (indexReader == null) {
            return -1;
        }
        return indexReader.numDocs();
    }
}
