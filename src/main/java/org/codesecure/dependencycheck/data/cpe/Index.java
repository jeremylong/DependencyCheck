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
package org.codesecure.dependencycheck.data.cpe;

import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.core.KeywordAnalyzer;
import org.apache.lucene.analysis.miscellaneous.PerFieldAnalyzerWrapper;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StoredField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.Term;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.util.Version;
import org.codesecure.dependencycheck.data.lucene.AbstractIndex;
import org.codesecure.dependencycheck.utils.Settings;
import org.codesecure.dependencycheck.data.lucene.FieldAnalyzer;
import org.codesecure.dependencycheck.data.lucene.SearchFieldAnalyzer;

/**
 * The Index class is used to utilize and maintain the CPE Index.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Index extends AbstractIndex {

    /**
     * Returns the directory that holds the CPE Index.
     *
     * @return the Directory containing the CPE Index.
     * @throws IOException is thrown if an IOException occurs.
     */
    public Directory getDirectory() throws IOException {
        File path = getDataDirectory();
        Directory dir = FSDirectory.open(path);

        return dir;
    }

    /**
     * Retrieves the directory that the JAR file exists in so that
     * we can ensure we always use a common data directory.
     *
     * @return the data directory for this index.
     * @throws IOException is thrown if an IOException occurs of course...
     */
    public File getDataDirectory() throws IOException {
        String fileName = Settings.getString(Settings.KEYS.CPE_INDEX);
        String filePath = Index.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        String decodedPath = URLDecoder.decode(filePath, "UTF-8");
        File exePath = new File(decodedPath);
        if (exePath.getName().toLowerCase().endsWith(".jar")) {
            exePath = exePath.getParentFile();
        } else {
            exePath = new File(".");
        }
        File path = new File(exePath.getCanonicalFile() + File.separator + fileName);
        path = new File(path.getCanonicalPath());
        if (!path.exists()) {
            if (!path.mkdirs()) {
                throw new IOException("Unable to create CPE Data directory");
            }
        }
        return path;
    }

    /**
     * Creates an Analyzer for the CPE Index.
     *
     * @return the CPE Analyzer.
     */
    @SuppressWarnings("unchecked")
    public Analyzer createIndexingAnalyzer() {
        Map fieldAnalyzers = new HashMap();

        fieldAnalyzers.put(Fields.VERSION, new KeywordAnalyzer());
        fieldAnalyzers.put(Fields.NAME, new KeywordAnalyzer());

        PerFieldAnalyzerWrapper wrapper = new PerFieldAnalyzerWrapper(
                new FieldAnalyzer(Version.LUCENE_40), fieldAnalyzers);

        return wrapper;
    }
    private SearchFieldAnalyzer productSearchFieldAnalyzer = null;
    private SearchFieldAnalyzer vendorSearchFieldAnalyzer = null;

    /**
     * Creates an Analyzer for searching the CPE Index.
     *
     * @return the CPE Analyzer.
     */
    @SuppressWarnings("unchecked")
    public Analyzer createSearchingAnalyzer() {
        Map fieldAnalyzers = new HashMap();

        fieldAnalyzers.put(Fields.VERSION, new KeywordAnalyzer());
        fieldAnalyzers.put(Fields.NAME, new KeywordAnalyzer());
        productSearchFieldAnalyzer = new SearchFieldAnalyzer(Version.LUCENE_40);
        vendorSearchFieldAnalyzer = new SearchFieldAnalyzer(Version.LUCENE_40);
        fieldAnalyzers.put(Fields.PRODUCT, productSearchFieldAnalyzer);
        fieldAnalyzers.put(Fields.VENDOR, vendorSearchFieldAnalyzer);

        PerFieldAnalyzerWrapper wrapper = new PerFieldAnalyzerWrapper(
                new FieldAnalyzer(Version.LUCENE_40), fieldAnalyzers);

        return wrapper;
    }

    /**
     * Creates the Lucene QueryParser used when querying the index
     * @return a QueryParser.
     */
    public QueryParser createQueryParser() {
        return new QueryParser(Version.LUCENE_40, Fields.NAME, getSearchingAnalyzer());
    }

    /**
     * Resets the searching analyzers
     */
    protected void resetSearchingAnalyzer() {
        if (productSearchFieldAnalyzer != null) {
            productSearchFieldAnalyzer.clear();
        }
        if (vendorSearchFieldAnalyzer != null) {
            vendorSearchFieldAnalyzer.clear();
        }
    }

    /**
     * Saves a CPE Entry into the Lucene index.
     *
     * @param entry a CPE entry.
     * @throws CorruptIndexException is thrown if the index is corrupt.
     * @throws IOException is thrown if an IOException occurs.
     */
    public void saveEntry(Entry entry) throws CorruptIndexException, IOException {
        Document doc = convertEntryToDoc(entry);
        //Term term = new Term(Fields.NVDID, LuceneUtils.escapeLuceneQuery(entry.getNvdId()));
        Term term = new Term(Fields.NAME, entry.getName());
        indexWriter.updateDocument(term, doc);
    }

    /**
     * Converts a CPE entry into a Lucene Document.
     *
     * @param entry a CPE Entry.
     * @return a Lucene Document containing a CPE Entry.
     */
    protected Document convertEntryToDoc(Entry entry) {
        Document doc = new Document();

        Field name = new StoredField(Fields.NAME, entry.getName());
        doc.add(name);

        Field vendor = new TextField(Fields.VENDOR, entry.getVendor(), Field.Store.NO);
        vendor.setBoost(5.0F);
        doc.add(vendor);

        Field product = new TextField(Fields.PRODUCT, entry.getProduct(), Field.Store.NO);
        product.setBoost(5.0F);
        doc.add(product);

        //TODO revision should likely be its own field
        if (entry.getVersion() != null) {
            Field version = null;
            if (entry.getRevision() != null) {
                version = new TextField(Fields.VERSION, entry.getVersion() + " "
                        + entry.getRevision(), Field.Store.NO);
            } else {
                version = new TextField(Fields.VERSION, entry.getVersion(),
                        Field.Store.NO);
            }
            version.setBoost(0.8F);
            doc.add(version);
        }
        return doc;
    }
}
