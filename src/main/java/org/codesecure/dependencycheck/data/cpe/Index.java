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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
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
import org.joda.time.DateTime;
import org.joda.time.Days;

/**
 * The Index class is used to utilize and maintain the CPE Index.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Index {

    /**
     * Te name of the properties file containing the timestamp of the last update.
     */
    private static final String UPDATE_PROPERTIES_FILE = "lastupdated.prop";
    /**
     * The properties file key for the last updated field.
     */
    private static final String LAST_UPDATED = "lastupdated";
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
                writeLastUpdatedPropertyFile();
            } catch (Exception ex) {
                Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                boolean deleted = false;
                try {
                    deleted = outputPath.delete();
                } finally {
                    if (!deleted) {
                        outputPath.deleteOnExit();
                    }
                }
            }
        }
    }

    private void writeLastUpdatedPropertyFile() {
        DateTime now = new DateTime();
        String dir = Settings.getString(Settings.KEYS.CPE_INDEX);
        File cpeProp = new File(dir + File.separatorChar + UPDATE_PROPERTIES_FILE);
        Properties prop = new Properties();
        prop.put(this.LAST_UPDATED, String.valueOf(now.getMillis()));
        OutputStream os = null;
        try {
            os = new FileOutputStream(cpeProp);
            OutputStreamWriter out = new OutputStreamWriter(os);
            prop.store(out, dir);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                os.flush();
            } catch (IOException ex) {
                Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
            }
            try {
                os.close();
            } catch (IOException ex) {
                Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    /**
     * Determines if the index needs to be updated.
     *
     * @return whether or not the CPE Index needs to be updated.
     */
    public boolean updateNeeded() {
        boolean needed = false;
        String lastUpdated = null;
        String dir = Settings.getString(Settings.KEYS.CPE_INDEX);
        File f = new File(dir);
        if (!f.exists()) {
            needed = true;
        } else {
            File cpeProp = new File(dir + File.separatorChar + UPDATE_PROPERTIES_FILE);
            if (!cpeProp.exists()) {
                needed = true;
            } else {
                Properties prop = new Properties();
                FileInputStream is = null;
                try {
                    is = new FileInputStream(cpeProp);
                    prop.load(is);
                    lastUpdated = prop.getProperty(this.LAST_UPDATED);
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
                }
                try {
                    long lastupdate = Long.parseLong(lastUpdated);
                    DateTime last = new DateTime(lastupdate);
                    DateTime now = new DateTime();
                    Days d = Days.daysBetween(last, now);
                    int days = d.getDays();
                    int freq = Settings.getInt(Settings.KEYS.CPE_DOWNLOAD_FREQUENCY);
                    if (days >= freq) {
                        needed = true;
                    }
                } catch (NumberFormatException ex) {
                    needed = true;
                }
            }
        }
        return needed;
    }
}
