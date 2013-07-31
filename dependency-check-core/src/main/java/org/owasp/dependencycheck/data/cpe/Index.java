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
package org.owasp.dependencycheck.data.cpe;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.core.KeywordAnalyzer;
import org.apache.lucene.analysis.miscellaneous.PerFieldAnalyzerWrapper;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.Term;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.util.Version;
import org.owasp.dependencycheck.data.lucene.AbstractIndex;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.data.lucene.FieldAnalyzer;
import org.owasp.dependencycheck.data.lucene.SearchFieldAnalyzer;

/**
 * The Index class is used to utilize and maintain the CPE Index.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class Index extends AbstractIndex {

    /**
     * Returns the directory that holds the CPE Index.
     *
     * @return the Directory containing the CPE Index.
     * @throws IOException is thrown if an IOException occurs.
     */
    @Override
    public Directory getDirectory() throws IOException {
        final File path = getDataDirectory();
        return FSDirectory.open(path);
    }

    /**
     * Retrieves the directory that the JAR file exists in so that we can ensure
     * we always use a common data directory.
     *
     * @return the data directory for this index.
     * @throws IOException is thrown if an IOException occurs of course...
     */
    public File getDataDirectory() throws IOException {
        final String fileName = Settings.getString(Settings.KEYS.CPE_DATA_DIRECTORY);
        final String dataDirectory = Settings.getString(Settings.KEYS.DATA_DIRECTORY);
        //final File path = FileUtils.getDataDirectory(fileName, Index.class);
        final File path = new File(dataDirectory, fileName);
        if (!path.exists() && !path.mkdirs()) {
            throw new IOException("Unable to create CPE Data directory");
        }
        return path;
    }

    /**
     * Creates an Analyzer for the CPE Index.
     *
     * @return the CPE Analyzer.
     */
    @SuppressWarnings("unchecked")
    @Override
    public Analyzer createIndexingAnalyzer() {
        final Map fieldAnalyzers = new HashMap();
        fieldAnalyzers.put(Fields.DOCUMENT_KEY, new KeywordAnalyzer());
        return new PerFieldAnalyzerWrapper(new FieldAnalyzer(Version.LUCENE_43), fieldAnalyzers);
    }
    /**
     * The search field analyzer for the product field.
     */
    private SearchFieldAnalyzer productSearchFieldAnalyzer;
    /**
     * The search field analyzer for the vendor field.
     */
    private SearchFieldAnalyzer vendorSearchFieldAnalyzer;

    /**
     * Creates an Analyzer for searching the CPE Index.
     *
     * @return the CPE Analyzer.
     */
    @SuppressWarnings("unchecked")
    @Override
    public Analyzer createSearchingAnalyzer() {
        final Map fieldAnalyzers = new HashMap();

        fieldAnalyzers.put(Fields.DOCUMENT_KEY, new KeywordAnalyzer());
        productSearchFieldAnalyzer = new SearchFieldAnalyzer(Version.LUCENE_43);
        vendorSearchFieldAnalyzer = new SearchFieldAnalyzer(Version.LUCENE_43);
        fieldAnalyzers.put(Fields.PRODUCT, productSearchFieldAnalyzer);
        fieldAnalyzers.put(Fields.VENDOR, vendorSearchFieldAnalyzer);

        return new PerFieldAnalyzerWrapper(new FieldAnalyzer(Version.LUCENE_43), fieldAnalyzers);
    }

    /**
     * Creates the Lucene QueryParser used when querying the index.
     *
     * @return a QueryParser.
     */
    @Override
    public QueryParser createQueryParser() {
        return new QueryParser(Version.LUCENE_43, Fields.DOCUMENT_KEY, getSearchingAnalyzer());
    }

    /**
     * Resets the searching analyzers
     */
    @Override
    protected void resetSearchingAnalyzer() {
        if (productSearchFieldAnalyzer != null) {
            productSearchFieldAnalyzer.clear();
        }
        if (vendorSearchFieldAnalyzer != null) {
            vendorSearchFieldAnalyzer.clear();
        }
    }

    /**
     * Saves a CPE IndexEntry into the Lucene index.
     *
     * @param entry a CPE entry.
     * @throws CorruptIndexException is thrown if the index is corrupt.
     * @throws IOException is thrown if an IOException occurs.
     */
    public void saveEntry(IndexEntry entry) throws CorruptIndexException, IOException {
        final Document doc = convertEntryToDoc(entry);
        final Term term = new Term(Fields.DOCUMENT_KEY, entry.getDocumentId());
        getIndexWriter().updateDocument(term, doc);
    }

    /**
     * Converts a CPE entry into a Lucene Document.
     *
     * @param entry a CPE IndexEntry.
     * @return a Lucene Document containing a CPE IndexEntry.
     */
    protected Document convertEntryToDoc(IndexEntry entry) {
        final Document doc = new Document();

        final Field vendor = new TextField(Fields.VENDOR, entry.getVendor(), Field.Store.YES);
        doc.add(vendor);

        final Field product = new TextField(Fields.PRODUCT, entry.getProduct(), Field.Store.YES);
        doc.add(product);
        return doc;
    }
}
