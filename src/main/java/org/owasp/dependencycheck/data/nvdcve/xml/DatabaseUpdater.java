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
package org.owasp.dependencycheck.data.nvdcve.xml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import javax.xml.parsers.ParserConfigurationException;
import org.owasp.dependencycheck.data.CachedWebDataSource;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.SQLException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.owasp.dependencycheck.data.UpdateException;
import org.owasp.dependencycheck.data.cpe.Index;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.xml.sax.SAXException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class DatabaseUpdater implements CachedWebDataSource {

    /**
     * The name of the properties file containing the timestamp of the last
     * update.
     */
    private static final String UPDATE_PROPERTIES_FILE = "lastupdated.prop";
    /**
     * The properties file key for the last updated field - used to store the
     * last updated time of the Modified NVD CVE xml file.
     */
    private static final String LAST_UPDATED_MODIFIED = "lastupdated.modified";
    /**
     * Stores the last updated time for each of the NVD CVE files. These
     * timestamps should be updated if we process the modified file within 7
     * days of the last update.
     */
    private static final String LAST_UPDATED_BASE = "lastupdated.";
    /**
     * The current version of the database.
     */
    public static final String DATABASE_VERSION = "2.2";

    /**
     * <p>Downloads the latest NVD CVE XML file from the web and imports it into
     * the current CVE Database.</p>
     *
     * @throws UpdateException is thrown if there is an error updating the
     * database
     */
    public void update() throws UpdateException {
        try {
            final Map<String, NvdCveUrl> update = updateNeeded();
            int maxUpdates = 0;
            for (NvdCveUrl cve : update.values()) {
                if (cve.getNeedsUpdate()) {
                    maxUpdates += 1;
                }
            }
            if (maxUpdates > 3) {
                Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.WARNING,
                        "NVD CVE requires several updates; this could take a couple of minutes.");
            }
            int count = 0;
            for (NvdCveUrl cve : update.values()) {
                if (cve.getNeedsUpdate()) {
                    count += 1;
                    Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.WARNING,
                            "Updating NVD CVE ({0} of {1})", new Object[]{count, maxUpdates});
                    URL url = new URL(cve.getUrl());
                    File outputPath = null;
                    File outputPath12 = null;
                    try {
                        Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.WARNING,
                                "Downloading {0}", cve.getUrl());

                        outputPath = File.createTempFile("cve" + cve.getId() + "_", ".xml");
                        Downloader.fetchFile(url, outputPath, false);

                        url = new URL(cve.getOldSchemaVersionUrl());
                        outputPath12 = File.createTempFile("cve_1_2_" + cve.getId() + "_", ".xml");
                        Downloader.fetchFile(url, outputPath12, false);

                        Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.WARNING,
                                "Processing {0}", cve.getUrl());
                        importXML(outputPath, outputPath12);

                        Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.WARNING,
                                "Completed updated {0} of {1}", new Object[]{count, maxUpdates});
                    } catch (FileNotFoundException ex) {
                        throw new UpdateException(ex);
                    } catch (ParserConfigurationException ex) {
                        throw new UpdateException(ex);
                    } catch (SAXException ex) {
                        throw new UpdateException(ex);
                    } catch (IOException ex) {
                        throw new UpdateException(ex);
                    } catch (SQLException ex) {
                        throw new UpdateException(ex);
                    } catch (DatabaseException ex) {
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
            }
            if (maxUpdates >= 1) {
                writeLastUpdatedPropertyFile(update);
            }
        } catch (MalformedURLException ex) {
            throw new UpdateException(ex);
        } catch (DownloadFailedException ex) {
            throw new UpdateException(ex);
        }
    }

    /**
     * Imports the NVD CVE XML File into the Lucene Index.
     *
     * @param file the file containing the NVD CVE XML
     * @param oldVersion contains the file containing the NVD CVE XML 1.2
     * @throws ParserConfigurationException is thrown if there is a parser configuration exception
     * @throws SAXException is thrown if there is a saxexception
     * @throws IOException is thrown if there is a ioexception
     * @throws SQLException is thrown if there is a sql exception
     * @throws DatabaseException is thrown if there is a database exception
     */
    private void importXML(File file, File oldVersion)
            throws ParserConfigurationException, SAXException, IOException, SQLException, DatabaseException {
        CveDB cveDB = null;
        Index cpeIndex = null;

        try {
            cveDB = new CveDB();
            cveDB.open();

            cpeIndex = new Index();
            cpeIndex.openIndexWriter();

            final SAXParserFactory factory = SAXParserFactory.newInstance();
            final SAXParser saxParser = factory.newSAXParser();

            NvdCve12Handler cve12Handler = new NvdCve12Handler();
            saxParser.parse(oldVersion, cve12Handler);
            final Map<String, List<VulnerableSoftware>> prevVersionVulnMap = cve12Handler.getVulnerabilities();
            cve12Handler = null;

            NvdCve20Handler cve20Handler = new NvdCve20Handler();
            cve20Handler.setCveDB(cveDB);
            cve20Handler.setPrevVersionVulnMap(prevVersionVulnMap);
            cve20Handler.setCpeIndex(cpeIndex);
            saxParser.parse(file, cve20Handler);

//            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.WARNING,
//                    String.format("%d out of %d entries processed were application specific CVEs.",
//                    cve20Handler.getTotalNumberOfApplicationEntries(),
//                    cve20Handler.getTotalNumberOfEntries()));

            cve20Handler = null;
        } finally {
            if (cpeIndex != null) {
                cpeIndex.close();
                cpeIndex = null;
            }
            if (cveDB != null) {
                cveDB.close();
                cveDB = null;
            }
        }
    }

    //<editor-fold defaultstate="collapsed" desc="Code to read/write properties files regarding the last update dates">
    /**
     * Writes a properties file containing the last updated date to the
     * VULNERABLE_CPE directory.
     *
     * @param updated a map of the updated nvdcve
     * @throws UpdateException is thrown if there is an update exception
     */
    private void writeLastUpdatedPropertyFile(Map<String, NvdCveUrl> updated) throws UpdateException {
        String dir;
        try {
            dir = CveDB.getDataDirectory().getCanonicalPath();
        } catch (IOException ex) {
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException("Unable to locate last updated properties file.", ex);
        }
        final File cveProp = new File(dir + File.separatorChar + UPDATE_PROPERTIES_FILE);
        final Properties prop = new Properties();
        prop.put("version", DATABASE_VERSION);
        for (NvdCveUrl cve : updated.values()) {
            prop.put(LAST_UPDATED_BASE + cve.id, String.valueOf(cve.getTimestamp()));
        }

        OutputStream os = null;
        OutputStreamWriter out = null;
        try {
            os = new FileOutputStream(cveProp);
            out = new OutputStreamWriter(os, "UTF-8");
            prop.store(out, dir);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException("Unable to find last updated properties file.", ex);
        } catch (IOException ex) {
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException("Unable to update last updated properties file.", ex);
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ex) {
                    Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    /**
     * Determines if the index needs to be updated. This is done by fetching the
     * nvd cve meta data and checking the last update date. If the data needs to
     * be refreshed this method will return the NvdCveUrl for the files that
     * need to be updated.
     *
     * @return the NvdCveUrl of the files that need to be updated.
     * @throws MalformedURLException is thrown if the URL for the NVD CVE Meta
     * data is incorrect.
     * @throws DownloadFailedException is thrown if there is an error.
     * downloading the nvd cve download data file.
     * @throws UpdateException Is thrown if there is an issue with the last
     * updated properties file.
     */
    public Map<String, NvdCveUrl> updateNeeded() throws MalformedURLException, DownloadFailedException, UpdateException {

        Map<String, NvdCveUrl> currentlyPublished;
        try {
            currentlyPublished = retrieveCurrentTimestampsFromWeb();
        } catch (InvalidDataException ex) {
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new DownloadFailedException("Unable to retrieve valid timestamp from nvd cve downloads page", ex);

        } catch (InvalidSettingException ex) {
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new DownloadFailedException("Invalid settings", ex);
        }

        if (currentlyPublished == null) {
            throw new DownloadFailedException("Unable to retrieve valid timestamp from nvd cve downloads page");
        }
        String dir;
        try {
            dir = CveDB.getDataDirectory().getCanonicalPath();
        } catch (IOException ex) {
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.SEVERE, null, ex);
            throw new UpdateException("Unable to locate last updated properties file.", ex);
        }

        final File f = new File(dir);
        if (f.exists()) {
            final File cveProp = new File(dir + File.separatorChar + UPDATE_PROPERTIES_FILE);
            if (cveProp.exists()) {
                final Properties prop = new Properties();
                InputStream is = null;
                try {
                    is = new FileInputStream(cveProp);
                    prop.load(is);

                    boolean deleteAndRecreate = false;
                    float version = 0;

                    if (prop.getProperty("version") == null) {
                        deleteAndRecreate = true;
                    } else {
                        try {
                            version = Float.parseFloat(prop.getProperty("version"));
                            final float currentVersion = Float.parseFloat(DATABASE_VERSION);
                            if (currentVersion > version) {
                                deleteAndRecreate = true;
                            }
                        } catch (NumberFormatException ex) {
                            deleteAndRecreate = true;
                        }
                    }
                    if (deleteAndRecreate) {
                        Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.WARNING, "Index version is old. Rebuilding the index.");
                        is.close();
                        //this is an old version of the lucene index - just delete it
                        FileUtils.delete(f);

                        //this importer also updates the CPE index and it is also using an old version
                        final Index cpeid = new Index();
                        final File cpeDir = cpeid.getDataDirectory();
                        FileUtils.delete(cpeDir);
                        return currentlyPublished;
                    }

                    final long lastUpdated = Long.parseLong(prop.getProperty(LAST_UPDATED_MODIFIED));
                    final Date now = new Date();
                    final int days = Settings.getInt(Settings.KEYS.CVE_MODIFIED_VALID_FOR_DAYS);
                    final int maxEntries = Settings.getInt(Settings.KEYS.CVE_URL_COUNT);
                    if (lastUpdated == currentlyPublished.get("modified").timestamp) {
                        currentlyPublished.clear(); //we don't need to update anything.
                    } else if (withinRange(lastUpdated, now.getTime(), days)) {
                        currentlyPublished.get("modified").setNeedsUpdate(true);
                        for (int i = 1; i <= maxEntries; i++) {
                            currentlyPublished.get(String.valueOf(i)).setNeedsUpdate(false);
                        }
                    } else { //we figure out which of the several XML files need to be downloaded.
                        currentlyPublished.get("modified").setNeedsUpdate(false);
                        for (int i = 1; i <= maxEntries; i++) {
                            final NvdCveUrl cve = currentlyPublished.get(String.valueOf(i));
                            long currentTimestamp = 0;
                            try {
                                currentTimestamp = Long.parseLong(prop.getProperty(LAST_UPDATED_BASE + String.valueOf(i), "0"));
                            } catch (NumberFormatException ex) {
                                Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINEST, "Error parsing " + LAST_UPDATED_BASE
                                        + String.valueOf(i) + " from nvdcve.lastupdated", ex);
                            }
                            if (currentTimestamp == cve.getTimestamp()) {
                                cve.setNeedsUpdate(false); //they default to true.
                            }
                        }
                    }
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINEST, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINEST, null, ex);
                } catch (NumberFormatException ex) {
                    Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINEST, null, ex);
                } finally {
                    if (is != null) {
                        try {
                            is.close();
                        } catch (IOException ex) {
                            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                }
            }
        }
        return currentlyPublished;
    }

    /**
     * Determines if the epoch date is within the range specified of the
     * compareTo epoch time. This takes the (compareTo-date)/1000/60/60/24 to
     * get the number of days. If the calculated days is less then the range the
     * date is considered valid.
     *
     * @param date the date to be checked.
     * @param compareTo the date to compare to.
     * @param range the range in days to be considered valid.
     * @return whether or not the date is within the range.
     */
    private boolean withinRange(long date, long compareTo, int range) {
        final double differenceInDays = (compareTo - date) / 1000.0 / 60.0 / 60.0 / 24.0;
        return differenceInDays < range;
    }

    /**
     * Retrieves the timestamps from the NVD CVE meta data file.
     *
     * @return the timestamp from the currently published nvdcve downloads page
     * @throws MalformedURLException thrown if the URL for the NVD CCE Meta data
     * is incorrect.
     * @throws DownloadFailedException thrown if there is an error downloading
     * the nvd cve meta data file
     * @throws InvalidDataException thrown if there is an exception parsing the
     * timestamps
     * @throws InvalidSettingException thrown if the settings are invalid
     */
    protected Map<String, NvdCveUrl> retrieveCurrentTimestampsFromWeb()
            throws MalformedURLException, DownloadFailedException, InvalidDataException, InvalidSettingException {

        final Map<String, NvdCveUrl> map = new HashMap<String, NvdCveUrl>();
        String retrieveUrl = Settings.getString(Settings.KEYS.CVE_MODIFIED_20_URL);

        NvdCveUrl item = new NvdCveUrl();
        item.setNeedsUpdate(false); //the others default to true, to make life easier later this should default to false.
        item.setId("modified");
        item.setUrl(retrieveUrl);
        item.setOldSchemaVersionUrl(Settings.getString(Settings.KEYS.CVE_MODIFIED_12_URL));

        item.timestamp = Downloader.getLastModified(new URL(retrieveUrl));
        map.put("modified", item);

        final int max = Settings.getInt(Settings.KEYS.CVE_URL_COUNT);
        for (int i = 1; i <= max; i++) {
            retrieveUrl = Settings.getString(Settings.KEYS.CVE_BASE_URL + Settings.KEYS.CVE_SCHEMA_2_0 + i);
            item = new NvdCveUrl();
            item.setId(Integer.toString(i));
            item.setUrl(retrieveUrl);
            item.setOldSchemaVersionUrl(Settings.getString(Settings.KEYS.CVE_BASE_URL + Settings.KEYS.CVE_SCHEMA_1_2 + i));
            item.setTimestamp(Downloader.getLastModified(new URL(retrieveUrl)));
            map.put(item.id, item);
        }
        return map;
    }

    /**
     * A pojo that contains the Url and timestamp of the current NvdCve XML
     * files.
     */
    protected static class NvdCveUrl {

        /**
         * an id.
         */
        private String id;

        /**
         * Get the value of id.
         *
         * @return the value of id
         */
        public String getId() {
            return id;
        }

        /**
         * Set the value of id.
         *
         * @param id new value of id
         */
        public void setId(String id) {
            this.id = id;
        }
        /**
         * a url.
         */
        private String url;

        /**
         * Get the value of url.
         *
         * @return the value of url
         */
        public String getUrl() {
            return url;
        }

        /**
         * Set the value of url.
         *
         * @param url new value of url
         */
        public void setUrl(String url) {
            this.url = url;
        }
        /**
         * The 1.2 schema URL.
         */
        private String oldSchemaVersionUrl;

        /**
         * Get the value of oldSchemaVersionUrl.
         *
         * @return the value of oldSchemaVersionUrl
         */
        public String getOldSchemaVersionUrl() {
            return oldSchemaVersionUrl;
        }

        /**
         * Set the value of oldSchemaVersionUrl.
         *
         * @param oldSchemaVersionUrl new value of oldSchemaVersionUrl
         */
        public void setOldSchemaVersionUrl(String oldSchemaVersionUrl) {
            this.oldSchemaVersionUrl = oldSchemaVersionUrl;
        }
        /**
         * a timestamp - epoch time.
         */
        private long timestamp;

        /**
         * Get the value of timestamp - epoch time.
         *
         * @return the value of timestamp - epoch time
         */
        public long getTimestamp() {
            return timestamp;
        }

        /**
         * Set the value of timestamp - epoch time.
         *
         * @param timestamp new value of timestamp - epoch time
         */
        public void setTimestamp(long timestamp) {
            this.timestamp = timestamp;
        }
        /**
         * indicates whether or not this item should be updated.
         */
        private boolean needsUpdate = true;

        /**
         * Get the value of needsUpdate.
         *
         * @return the value of needsUpdate
         */
        public boolean getNeedsUpdate() {
            return needsUpdate;
        }

        /**
         * Set the value of needsUpdate.
         *
         * @param needsUpdate new value of needsUpdate
         */
        public void setNeedsUpdate(boolean needsUpdate) {
            this.needsUpdate = needsUpdate;
        }
    }
    //</editor-fold>
}
