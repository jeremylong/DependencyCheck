package org.codesecure.dependencycheck.data.cpe;
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.core.KeywordAnalyzer;
import org.apache.lucene.analysis.miscellaneous.PerFieldAnalyzerWrapper;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.util.Version;
import org.codesecure.dependencycheck.data.lucene.AbstractIndex;
import org.codesecure.dependencycheck.data.CachedWebDataSource;
import org.codesecure.dependencycheck.data.UpdateException;
import org.codesecure.dependencycheck.utils.Downloader;
import org.codesecure.dependencycheck.utils.Settings;
import org.codesecure.dependencycheck.data.cpe.xml.Importer;
import org.codesecure.dependencycheck.utils.DownloadFailedException;
import org.xml.sax.SAXException;

/**
 * The Index class is used to utilize and maintain the CPE Index.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Index extends AbstractIndex implements CachedWebDataSource {

    /**
     * The name of the properties file containing the timestamp of the last
     * update.
     */
    private static final String UPDATE_PROPERTIES_FILE = "lastupdated.prop";
    /**
     * The properties file key for the last updated field.
     */
    private static final String LAST_UPDATED = "lastupdated";

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
    protected File getDataDirectory() throws IOException {
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
    public Analyzer createAnalyzer() {
        Map fieldAnalyzers = new HashMap();

        fieldAnalyzers.put(Fields.VERSION, new KeywordAnalyzer());
        fieldAnalyzers.put(Fields.NAME, new KeywordAnalyzer());

        PerFieldAnalyzerWrapper wrapper = new PerFieldAnalyzerWrapper(
                new StandardAnalyzer(Version.LUCENE_40), fieldAnalyzers);

        return wrapper;
    }

    /**
     * Downloads the latest CPE XML file from the web and imports it into the
     * current CPE Index.
     *
     * @throws UpdateException is thrown if there is a problem updating the
     * index.
     */
    public void update() throws UpdateException {
        try {
            long timeStamp = updateNeeded();
            if (timeStamp > 0) {
                URL url = new URL(Settings.getString(Settings.KEYS.CPE_URL));
                Logger.getLogger(Index.class.getName()).log(Level.WARNING, "Updating CPE :" + url.toString());
                File outputPath = null;
                try {
                    outputPath = File.createTempFile("cpe", ".xml");
                    Downloader.fetchFile(url, outputPath, true);
                    Importer.importXML(outputPath.toString());
                    writeLastUpdatedPropertyFile(timeStamp);
                } catch (ParserConfigurationException ex) {
                    //Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
                    throw new UpdateException(ex);
                } catch (SAXException ex) {
                    //Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
                    throw new UpdateException(ex);
                } catch (IOException ex) {
                    //Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
                    throw new UpdateException(ex);
                } finally {
                    try {
                        if (outputPath != null && outputPath.exists()) {
                            outputPath.delete();
                        }
                    } finally {
                        if (outputPath != null && outputPath.exists()) {
                            outputPath.deleteOnExit();
                        }
                    }
                }
            }
        } catch (MalformedURLException ex) {
            //Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException(ex);
        } catch (DownloadFailedException ex) {
            //Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException(ex);
        }
    }

    /**
     * Writes a properties file containing the last updated date to the CPE
     * directory.
     *
     * @param timeStamp the timestamp to write.
     */
    private void writeLastUpdatedPropertyFile(long timeStamp) throws UpdateException {
        String dir;
        try {
            dir = getDataDirectory().getCanonicalPath();
        } catch (IOException ex) {
            Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException("Unable to locate the last updated properties file.", ex);
        }
        File cpeProp = new File(dir + File.separatorChar + UPDATE_PROPERTIES_FILE);
        Properties prop = new Properties();
        prop.put(Index.LAST_UPDATED, String.valueOf(timeStamp));
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
     * Determines if the index needs to be updated. This is done by fetching the
     * cpe.meta data and checking the lastModifiedDate. If the CPE data needs to
     * be refreshed this method will return the timestamp of the new CPE. If an
     * update is not required this function will return 0.
     *
     * @return the timestamp of the currently published CPE.xml if the index
     * needs to be updated, otherwise returns 0..
     * @throws MalformedURLException is thrown if the URL for the CPE Meta data
     * is incorrect.
     * @throws DownloadFailedException is thrown if there is an error
     * downloading the cpe.meta data file.
     * @throws UpdateException is thrown if there is an error locating the last updated
     * properties file.
     */
    public long updateNeeded() throws MalformedURLException, DownloadFailedException, UpdateException {
        long retVal = 0;
        long lastUpdated = 0;
        long currentlyPublishedDate = retrieveCurrentCPETimestampFromWeb();
        if (currentlyPublishedDate == 0) {
            throw new DownloadFailedException("Unable to retrieve valid timestamp from cpe.meta file");
        }

        //String dir = Settings.getString(Settings.KEYS.CPE_INDEX);
        File f;
        try {
            f = getDataDirectory(); //new File(dir);
        } catch (IOException ex) {
            Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException("Unable to locate last updated properties file.", ex);
        }
        if (!f.exists()) {
            retVal = currentlyPublishedDate;
        } else {
            File cpeProp;
            try {
                cpeProp = new File(f.getCanonicalPath() + File.separatorChar + UPDATE_PROPERTIES_FILE);
            } catch (IOException ex) {
                Logger.getLogger(Index.class.getName()).log(Level.SEVERE, null, ex);
                throw new UpdateException("Unable to find last updated properties file.", ex);
            }
            if (!cpeProp.exists()) {
                retVal = currentlyPublishedDate;
            } else {
                Properties prop = new Properties();
                InputStream is = null;
                try {
                    is = new FileInputStream(cpeProp);
                    prop.load(is);
                    lastUpdated = Long.parseLong(prop.getProperty(Index.LAST_UPDATED));
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Index.class.getName()).log(Level.FINEST, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Index.class.getName()).log(Level.FINEST, null, ex);
                } catch (NumberFormatException ex) {
                    Logger.getLogger(Index.class.getName()).log(Level.FINEST, null, ex);
                }
                if (currentlyPublishedDate > lastUpdated) {
                    retVal = currentlyPublishedDate;
                }
            }
        }
        return retVal;
    }

    /**
     * Retrieves the timestamp from the CPE meta data file.
     *
     * @return the timestamp from the currently published cpe.meta.
     * @throws MalformedURLException is thrown if the URL for the CPE Meta data
     * is incorrect.
     * @throws DownloadFailedException is thrown if there is an error
     * downloading the cpe.meta data file.
     */
    private long retrieveCurrentCPETimestampFromWeb() throws MalformedURLException, DownloadFailedException {
        long timestamp = 0;
        File tmp = null;
        InputStream is = null;
        try {
            tmp = File.createTempFile("cpe", "meta");
            URL url = new URL(Settings.getString(Settings.KEYS.CPE_META_URL));
            Downloader.fetchFile(url, tmp);
            Properties prop = new Properties();
            is = new FileInputStream(tmp);
            prop.load(is);
            timestamp = Long.parseLong(prop.getProperty("lastModifiedDate"));
        } catch (IOException ex) {
            throw new DownloadFailedException("Unable to create temporary file for CPE Meta File download.", ex);
        } finally {
            try {
                if (is != null) {
                    try {
                        is.close();
                    } catch (IOException ex) {
                        Logger.getLogger(Index.class.getName()).log(Level.FINEST, null, ex);
                    }
                }
                if (tmp != null && tmp.exists()) {
                    tmp.delete();
                }
            } finally {
                if (tmp != null && tmp.exists()) {
                    tmp.deleteOnExit();
                }
            }
        }
        return timestamp;
    }
}
