package org.codesecure.dependencycheck.data.cpe;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.KeywordAnalyzer;
import org.apache.lucene.analysis.PerFieldAnalyzerWrapper;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.util.Version;
import org.codesecure.dependencycheck.utils.Downloader;
import org.codesecure.dependencycheck.utils.Settings;
import org.codesecure.dependencycheck.data.cpe.xml.Importer;

/**
 * The Index class is used to utilize and maintain the CPE Index.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Index {

    /**
     * The Lucene directory containing the index.
     */
    protected Directory directory = null;
    /**
     * The IndexWriter for the Lucene index.
     */
    protected IndexWriter indexWriter = null;

    /**
     * Opens the CPE Index.
     * @throws IOException is thrown if an IOException occurs opening the index.
     */
    public void open() throws IOException {
        directory = Index.getDirectory();

        Analyzer analyzer = Index.createAnalyzer(); //new StandardAnalyzer(Version.LUCENE_35);
        IndexWriterConfig conf = new IndexWriterConfig(Version.LUCENE_35, analyzer);
        indexWriter = new IndexWriter(directory, conf);
    }

    /**
     * Closes the CPE Index.
     *
     * @throws CorruptIndexException is thrown if the index is corrupt.
     * @throws IOException is thrown if an IOException occurs closing the index.
     */
    public void close() throws CorruptIndexException, IOException {
        indexWriter.commit();
        indexWriter.close(true);
        directory.close();
    }

    /**
     * Returns the directory that holds the CPE Index.
     *
     * @return the Directory containing the CPE Index.
     * @throws IOException is thrown if an IOException occurs.
     */
    public static Directory getDirectory() throws IOException {
        String fileName = Settings.getString(Settings.KEYS.CPE_INDEX);
        File path = new File(fileName);
        Directory directory = FSDirectory.open(path);

        return directory;
    }

    /**
     * Creates an Analyzer for the CPE Index.
     *
     * @return the CPE Analyzer.
     */
    public static Analyzer createAnalyzer() {
        Map fieldAnalyzers = new HashMap();

        fieldAnalyzers.put(Fields.VERSION, new KeywordAnalyzer());
        //new WhitespaceAnalyzer(Version.LUCENE_35)); //

        PerFieldAnalyzerWrapper wrapper = new PerFieldAnalyzerWrapper(
                new StandardAnalyzer(Version.LUCENE_35), fieldAnalyzers);

        return wrapper;
    }

    /**
     * Downloads the latest CPE XML file from the web and imports it into
     * the current CPE Index.
     *
     * @throws Exception is thrown if an exception occurs.
     */
    public void updateIndexFromWeb() throws Exception {
        if (updateNeeded()) {
            URL url = new URL(Settings.getString(Settings.KEYS.CPE_URL));
            File outputPath = null;
            try {
                outputPath = File.createTempFile("cpe", ".xml");
                Downloader.fetchFile(url, outputPath);
                Importer.importXML(outputPath.toString());
            } catch (Exception ex) {
                Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                outputPath.delete();
            }
        }
    }

    /**
     * Determines if the index needs to be updated.
     *
     * @return whether or not the CPE Index needs to be updated.
     */
    public boolean updateNeeded() {
        return true;
    }
}
