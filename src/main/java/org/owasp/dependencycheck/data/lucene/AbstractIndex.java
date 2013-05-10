/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Check. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.lucene;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.LockObtainFailedException;
import org.apache.lucene.util.Version;

/**
 * The base Index for other index objects. Implements the open and close
 * methods.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public abstract class AbstractIndex {

    /**
     * The Lucene directory containing the index.
     */
    private Directory directory;
    /**
     * The IndexWriter for the Lucene index.
     */
    private IndexWriter indexWriter;
    /**
     * The Lucene IndexReader.
     */
    private IndexReader indexReader;
    /**
     * The Lucene IndexSearcher.
     */
    private IndexSearcher indexSearcher;
    /**
     * The Lucene Analyzer used for Indexing.
     */
    private Analyzer indexingAnalyzer;
    /**
     * The Lucene Analyzer used for Searching.
     */
    private Analyzer searchingAnalyzer;
    /**
     * The Lucene QueryParser used for Searching.
     */
    private QueryParser queryParser;
    /**
     * Indicates whether or not the Lucene Index is open.
     */
    private boolean indexOpen = false;

    /**
     * Opens the CPE Index.
     *
     * @throws IOException is thrown if an IOException occurs opening the index.
     */
    public void open() throws IOException {
        directory = this.getDirectory();
        indexingAnalyzer = this.getIndexingAnalyzer();
        searchingAnalyzer = this.getSearchingAnalyzer();
        indexOpen = true;
    }

    /**
     * Closes the CPE Index.
     */
    public void close() {
        if (indexWriter != null) {
            try {
                indexWriter.commit();
            } catch (CorruptIndexException ex) {
                Logger.getLogger(AbstractIndex.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(AbstractIndex.class.getName()).log(Level.SEVERE, null, ex);
            }
            try {
                indexWriter.close(true);
            } catch (CorruptIndexException ex) {
                Logger.getLogger(AbstractIndex.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(AbstractIndex.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                indexWriter = null;
            }
        }
        if (indexSearcher != null) {
            indexSearcher = null;
        }

        if (indexingAnalyzer != null) {
            indexingAnalyzer.close();
            indexingAnalyzer = null;
        }

        if (searchingAnalyzer != null) {
            searchingAnalyzer.close();
            searchingAnalyzer = null;
        }

        try {
            directory.close();
        } catch (IOException ex) {
            Logger.getLogger(AbstractIndex.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            directory = null;
        }
        indexOpen = false;
    }

    /**
     * Returns the status of the data source - is the index open.
     *
     * @return true or false.
     */
    public boolean isOpen() {
        return indexOpen;
    }

    /**
     * Opens the Lucene Index Writer.
     *
     * @throws CorruptIndexException is thrown if the Lucene index is corrupt.
     * @throws IOException is thrown if an IOException occurs opening the index.
     */
    public void openIndexWriter() throws CorruptIndexException, IOException {
        if (!isOpen()) {
            open();
        }
        final IndexWriterConfig conf = new IndexWriterConfig(Version.LUCENE_40, indexingAnalyzer);
        indexWriter = new IndexWriter(directory, conf);
    }

    /**
     * Retrieves the IndexWriter for the Lucene Index.
     *
     * @return an IndexWriter.
     * @throws CorruptIndexException is thrown if the Lucene Index is corrupt.
     * @throws LockObtainFailedException is thrown if there is an exception
     * obtaining a lock on the Lucene index.
     * @throws IOException is thrown if an IOException occurs opening the index.
     */
    public IndexWriter getIndexWriter() throws CorruptIndexException, LockObtainFailedException, IOException {
        if (indexWriter == null) {
            openIndexWriter();
        }
        return indexWriter;
    }

    /**
     * Opens the Lucene Index for reading.
     *
     * @throws CorruptIndexException is thrown if the index is corrupt.
     * @throws IOException is thrown if there is an exception reading the index.
     */
    public void openIndexReader() throws CorruptIndexException, IOException {
        if (!isOpen()) {
            open();
        }
        //indexReader = IndexReader.open(directory, true);
        indexReader = DirectoryReader.open(directory);
    }

    /**
     * Returns an IndexSearcher for the Lucene Index.
     *
     * @return an IndexSearcher.
     * @throws CorruptIndexException is thrown if the index is corrupt.
     * @throws IOException is thrown if there is an exception reading the index.
     */
    protected IndexSearcher getIndexSearcher() throws CorruptIndexException, IOException {
        if (indexReader == null) {
            openIndexReader();
        }
        if (indexSearcher == null) {
            indexSearcher = new IndexSearcher(indexReader);
        }
        return indexSearcher;
    }

    /**
     * Returns an Analyzer to be used when indexing.
     *
     * @return an Analyzer.
     */
    public Analyzer getIndexingAnalyzer() {
        if (indexingAnalyzer == null) {
            indexingAnalyzer = createIndexingAnalyzer();
        }
        return indexingAnalyzer;
    }

    /**
     * Returns an analyzer used for searching the index
     * @return a lucene analyzer
     */
    protected Analyzer getSearchingAnalyzer() {
        if (searchingAnalyzer == null) {
            searchingAnalyzer = createSearchingAnalyzer();
        }
        return searchingAnalyzer;
    }

    /**
     * Gets a query parser
     * @return a query parser
     */
    protected QueryParser getQueryParser() {
        if (queryParser == null) {
            queryParser = createQueryParser();
        }
        return queryParser;
    }

    /**
     * Searches the index using the given search string.
     *
     * @param searchString the query text
     * @param maxQueryResults the maximum number of documents to return
     * @return the TopDocs found by the search
     * @throws ParseException thrown when the searchString is invalid
     * @throws IOException is thrown if there is an issue with the underlying Index
     */
    public TopDocs search(String searchString, int maxQueryResults) throws ParseException, IOException {

        final QueryParser parser = getQueryParser();
        final Query query = parser.parse(searchString);
        resetSearchingAnalyzer();
        final IndexSearcher is = getIndexSearcher();
        final TopDocs docs = is.search(query, maxQueryResults);

        return docs;
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
        final IndexSearcher is = getIndexSearcher();
        return is.search(query, maxQueryResults);
    }

    /**
     * Retrieves a document from the Index.
     *
     * @param documentId the id of the document to retrieve
     * @return the Document
     * @throws IOException thrown if there is an IOException
     */
    public Document getDocument(int documentId) throws IOException {
        final IndexSearcher is = getIndexSearcher();
        return is.doc(documentId);
    }

    /**
     * Gets the directory that contains the Lucene Index.
     *
     * @return a Lucene Directory
     * @throws IOException is thrown when an IOException occurs
     */
    public abstract Directory getDirectory() throws IOException;

    /**
     * Creates the Lucene Analyzer used when indexing.
     *
     * @return a Lucene Analyzer
     */
    public abstract Analyzer createIndexingAnalyzer();

    /**
     * Creates the Lucene Analyzer used when querying the index.
     *
     * @return a Lucene Analyzer
     */
    public abstract Analyzer createSearchingAnalyzer();

    /**
     * Creates the Lucene QueryParser used when querying the index.
     * @return a QueryParser
     */
    public abstract QueryParser createQueryParser();

    /**
     * Resets the searching analyzers
     */
    protected abstract void resetSearchingAnalyzer();
}
