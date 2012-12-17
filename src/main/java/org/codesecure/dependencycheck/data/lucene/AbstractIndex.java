package org.codesecure.dependencycheck.data.lucene;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.search.IndexSearcher;
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
    protected Directory directory = null;
    /**
     * The IndexWriter for the Lucene index.
     */
    protected IndexWriter indexWriter = null;
    /**
     * The Lucene IndexReader.
     */
    private IndexReader indexReader = null;
    /**
     * The Lucene IndexSearcher.
     */
    private IndexSearcher indexSearcher = null;
    /**
     * The Lucene Analyzer.
     */
    private Analyzer analyzer = null;
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
        analyzer = this.getAnalyzer(); //new StandardAnalyzer(Version.LUCENE_35);
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

        if (analyzer != null) {
            analyzer.close();
            analyzer = null;
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
        IndexWriterConfig conf = new IndexWriterConfig(Version.LUCENE_40, analyzer);
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
    public IndexSearcher getIndexSearcher() throws CorruptIndexException, IOException {
        if (indexReader == null) {
            openIndexReader();
        }
        if (indexSearcher == null) {
            indexSearcher = new IndexSearcher(indexReader);
        }
        return indexSearcher;
    }

    /**
     * Returns an Analyzer for the Lucene Index.
     *
     * @return an Analyzer.
     */
    public Analyzer getAnalyzer() {
        if (analyzer == null) {
            analyzer = createAnalyzer();
        }
        return analyzer;
    }

    /**
     * Gets the directory that contains the Lucene Index.
     *
     * @return a Lucene Directory.
     * @throws IOException is thrown when an IOException occurs.
     */
    public abstract Directory getDirectory() throws IOException;

    /**
     * Creates the Lucene Analyzer used when indexing and searching the index.
     *
     * @return a Lucene Analyzer.
     */
    public abstract Analyzer createAnalyzer();
}
