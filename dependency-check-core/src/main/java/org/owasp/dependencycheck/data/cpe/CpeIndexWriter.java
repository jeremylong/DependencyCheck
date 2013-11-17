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
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.Term;
import org.apache.lucene.util.Version;
import org.owasp.dependencycheck.data.lucene.FieldAnalyzer;
import org.owasp.dependencycheck.data.lucene.LuceneUtils;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class CpeIndexWriter extends BaseIndex {

    /**
     * The IndexWriter for the Lucene index.
     */
    private IndexWriter indexWriter;
    /**
     * The Lucene Analyzer used for Indexing.
     */
    private Analyzer indexingAnalyzer;

    /**
     * Opens the CPE Index.
     *
     * @throws IOException is thrown if an IOException occurs opening the index.
     */
    @Override
    public void open() throws IOException {
        //TODO add spinlock
        super.open();
        indexingAnalyzer = createIndexingAnalyzer();
        final IndexWriterConfig conf = new IndexWriterConfig(LuceneUtils.CURRENT_VERSION, indexingAnalyzer);
        indexWriter = new IndexWriter(getDirectory(), conf);
    }

    /**
     * Closes the CPE Index.
     */
    @Override
    public void close() {
        //TODO remove spinlock
        if (indexWriter != null) {
            commit();
            try {
                indexWriter.close(true);
            } catch (CorruptIndexException ex) {
                final String msg = "Unable to update database, there is a corrupt index.";
                Logger.getLogger(CpeIndexWriter.class.getName()).log(Level.SEVERE, msg);
                Logger.getLogger(CpeIndexWriter.class.getName()).log(Level.FINE, null, ex);
            } catch (IOException ex) {
                final String msg = "Unable to update database due to an IO error.";
                Logger.getLogger(CpeIndexWriter.class.getName()).log(Level.SEVERE, msg);
                Logger.getLogger(CpeIndexWriter.class.getName()).log(Level.FINE, null, ex);
            } finally {
                indexWriter = null;
            }
        }
        if (indexingAnalyzer != null) {
            indexingAnalyzer.close();
            indexingAnalyzer = null;
        }
        super.close();
    }

    /**
     * Commits any pending changes.
     */
    public void commit() {
        if (indexWriter != null) {
            try {
                indexWriter.forceMerge(1);
                indexWriter.commit();
            } catch (CorruptIndexException ex) {
                final String msg = "Unable to update database, there is a corrupt index.";
                Logger.getLogger(CpeIndexWriter.class.getName()).log(Level.SEVERE, msg);
                Logger.getLogger(CpeIndexWriter.class.getName()).log(Level.FINE, null, ex);
            } catch (IOException ex) {
                final String msg = "Unable to update database due to an IO error.";
                Logger.getLogger(CpeIndexWriter.class.getName()).log(Level.SEVERE, msg);
                Logger.getLogger(CpeIndexWriter.class.getName()).log(Level.FINE, null, ex);
            }
        }
    }

    /**
     * Creates the indexing analyzer for the CPE Index.
     *
     * @return the CPE Analyzer.
     */
    @SuppressWarnings("unchecked")
    private Analyzer createIndexingAnalyzer() {
        final Map fieldAnalyzers = new HashMap();
        fieldAnalyzers.put(Fields.DOCUMENT_KEY, new KeywordAnalyzer());
        return new PerFieldAnalyzerWrapper(new FieldAnalyzer(LuceneUtils.CURRENT_VERSION), fieldAnalyzers);
    }

    /**
     * Saves a CPE IndexEntry into the Lucene index.
     *
     * @param entry a CPE entry.
     * @throws CorruptIndexException is thrown if the index is corrupt.
     * @throws IOException is thrown if an IOException occurs.
     */
    public void saveEntry(IndexEntry entry) throws CorruptIndexException, IOException {
        final Document doc = new Document();
        final Field documentKey = new StringField(Fields.DOCUMENT_KEY, entry.getDocumentId(), Field.Store.NO);
        final Field vendor = new TextField(Fields.VENDOR, entry.getVendor(), Field.Store.YES);
        final Field product = new TextField(Fields.PRODUCT, entry.getProduct(), Field.Store.YES);
        doc.add(documentKey);
        doc.add(vendor);
        doc.add(product);

        final Term term = new Term(Fields.DOCUMENT_KEY, entry.getDocumentId());
        indexWriter.updateDocument(term, doc);
    }
}
