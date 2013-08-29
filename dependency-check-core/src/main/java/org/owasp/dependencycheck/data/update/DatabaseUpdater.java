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
package org.owasp.dependencycheck.data.update;

import org.owasp.dependencycheck.data.nvdcve.NvdCve12Handler;
import org.owasp.dependencycheck.data.nvdcve.NvdCve20Handler;
import org.owasp.dependencycheck.data.nvdcve.InvalidDataException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;
import org.owasp.dependencycheck.data.CachedWebDataSource;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.owasp.dependencycheck.data.UpdateException;
import org.owasp.dependencycheck.data.cpe.BaseIndex;
import org.owasp.dependencycheck.data.cpe.CpeIndexWriter;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import static org.owasp.dependencycheck.data.update.DataStoreMetaInfo.MODIFIED;
import org.owasp.dependencycheck.utils.InvalidSettingException;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class DatabaseUpdater implements CachedWebDataSource {

    /**
     * Utility to read and write meta-data about the data.
     */
    private DataStoreMetaInfo properties = null;
    /**
     * Reference to the Cve Database.
     */
    private CveDB cveDB = null;
    /**
     * Reference to the Cpe Index.
     */
    private CpeIndexWriter cpeIndex = null;
    /**
     * A flag indicating whether or not the batch update should be performed.
     */
    protected boolean doBatchUpdate;

    /**
     * Get the value of doBatchUpdate
     *
     * @return the value of doBatchUpdate
     */
    protected boolean isDoBatchUpdate() {
        return doBatchUpdate;
    }

    /**
     * Set the value of doBatchUpdate
     *
     * @param doBatchUpdate new value of doBatchUpdate
     */
    protected void setDoBatchUpdate(boolean doBatchUpdate) {
        this.doBatchUpdate = doBatchUpdate;
    }

    /**
     * <p>Downloads the latest NVD CVE XML file from the web and imports it into
     * the current CVE Database.</p>
     *
     * @throws UpdateException is thrown if there is an error updating the
     * database
     */
    @Override
    public void update() throws UpdateException {
        doBatchUpdate = false;
        properties = new DataStoreMetaInfo();
        try {
            final Map<String, NvdCveInfo> update = updateNeeded();
            int maxUpdates = 0;
            for (NvdCveInfo cve : update.values()) {
                if (cve.getNeedsUpdate()) {
                    maxUpdates += 1;
                }
            }
            if (maxUpdates > 3 && !properties.isBatchUpdateMode()) {
                Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.INFO,
                        "NVD CVE requires several updates; this could take a couple of minutes.");
            }
            if (maxUpdates > 0 && !isDoBatchUpdate()) {
                openDataStores();
            }

            if (properties.isBatchUpdateMode() && isDoBatchUpdate()) {
                try {
                    performBatchUpdate();
                    openDataStores();
                } catch (IOException ex) {
                    throw new UpdateException("Unable to perform batch update", ex);
                }
            }

            int count = 0;
            for (NvdCveInfo cve : update.values()) {
                if (cve.getNeedsUpdate()) {
                    count += 1;
                    Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.INFO,
                            "Updating NVD CVE ({0} of {1})", new Object[]{count, maxUpdates});
                    URL url = new URL(cve.getUrl());
                    File outputPath = null;
                    File outputPath12 = null;
                    try {
                        Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.INFO,
                                "Downloading {0}", cve.getUrl());
                        outputPath = File.createTempFile("cve" + cve.getId() + "_", ".xml");
                        Downloader.fetchFile(url, outputPath);

                        url = new URL(cve.getOldSchemaVersionUrl());
                        outputPath12 = File.createTempFile("cve_1_2_" + cve.getId() + "_", ".xml");
                        Downloader.fetchFile(url, outputPath12);

                        Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.INFO,
                                "Processing {0}", cve.getUrl());

                        importXML(outputPath, outputPath12);

                        cveDB.commit();
                        cpeIndex.commit();

                        properties.save(cve);

                        Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.INFO,
                                "Completed update {0} of {1}", new Object[]{count, maxUpdates});
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
                    } catch (ClassNotFoundException ex) {
                        throw new UpdateException(ex);
                    } finally {
                        boolean deleted = false;
                        try {
                            if (outputPath != null && outputPath.exists()) {
                                deleted = outputPath.delete();
                            }
                        } finally {
                            if (outputPath != null && (outputPath.exists() || !deleted)) {
                                outputPath.deleteOnExit();
                            }
                        }
                        try {
                            deleted = false;
                            if (outputPath12 != null && outputPath12.exists()) {
                                deleted = outputPath12.delete();
                            }
                        } finally {
                            if (outputPath12 != null && (outputPath12.exists() || !deleted)) {
                                outputPath12.deleteOnExit();
                            }
                        }
                    }
                }
            }
            if (maxUpdates >= 1) {
                properties.save(update.get(MODIFIED));
                cveDB.cleanupDatabase();
            }
        } catch (MalformedURLException ex) {
            throw new UpdateException(ex);
        } catch (DownloadFailedException ex) {
            throw new UpdateException(ex);
        } finally {
            closeDataStores();
        }
    }

    /**
     * Imports the NVD CVE XML File into the Lucene Index.
     *
     * @param file the file containing the NVD CVE XML
     * @param oldVersion contains the file containing the NVD CVE XML 1.2
     * @throws ParserConfigurationException is thrown if there is a parser
     * configuration exception
     * @throws SAXException is thrown if there is a SAXException
     * @throws IOException is thrown if there is a IO Exception
     * @throws SQLException is thrown if there is a SQL exception
     * @throws DatabaseException is thrown if there is a database exception
     * @throws ClassNotFoundException thrown if the h2 database driver cannot be
     * loaded
     */
    private void importXML(File file, File oldVersion)
            throws ParserConfigurationException, SAXException, IOException, SQLException, DatabaseException, ClassNotFoundException {

        final SAXParserFactory factory = SAXParserFactory.newInstance();
        final SAXParser saxParser = factory.newSAXParser();

        final NvdCve12Handler cve12Handler = new NvdCve12Handler();
        saxParser.parse(oldVersion, cve12Handler);
        final Map<String, List<VulnerableSoftware>> prevVersionVulnMap = cve12Handler.getVulnerabilities();

        final NvdCve20Handler cve20Handler = new NvdCve20Handler();
        cve20Handler.setCveDB(cveDB);
        cve20Handler.setPrevVersionVulnMap(prevVersionVulnMap);
        cve20Handler.setCpeIndex(cpeIndex);
        saxParser.parse(file, cve20Handler);
    }

    /**
     * Deletes the existing data directories.
     *
     * @throws IOException thrown if the directory cannot be deleted
     */
    protected void deleteExistingData() throws IOException {
        Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.INFO, "The database version is old. Rebuilding the database.");

        final File cveDir = CveDB.getDataDirectory();
        FileUtils.delete(cveDir);

        final File cpeDir = BaseIndex.getDataDirectory();
        FileUtils.delete(cpeDir);
    }

    private void performBatchUpdate() throws UpdateException {
        if (properties.isBatchUpdateMode() && doBatchUpdate) {
            final String batchSrc = Settings.getString(Settings.KEYS.BATCH_UPDATE_URL);
            File tmp = null;
            try {
                deleteExistingData();
                final File dataDirectory = CveDB.getDataDirectory().getParentFile();
                final URL batchUrl = new URL(batchSrc);
                if ("file".equals(batchUrl.getProtocol())) {
                    try {
                        tmp = new File(batchUrl.toURI());
                    } catch (URISyntaxException ex) {
                        final String msg = String.format("Invalid batch update URI: %s", batchSrc);
                        throw new UpdateException(msg, ex);
                    }
                } else if ("http".equals(batchUrl.getProtocol())
                        || "https".equals(batchUrl.getProtocol())) {
                    tmp = File.createTempFile("batch_", ".zip");
                    Downloader.fetchFile(batchUrl, tmp);
                }
                //TODO add FTP?
                FileUtils.extractFiles(tmp, dataDirectory);

            } catch (IOException ex) {
                final String msg = String.format("IO Exception Occured performing batch update using: %s", batchSrc);
                throw new UpdateException(msg, ex);
            } finally {
                if (tmp != null && !tmp.delete()) {
                    tmp.deleteOnExit();
                }
            }
        }
    }

    /**
     * Closes the CVE and CPE data stores.
     */
    private void closeDataStores() {
        if (cveDB != null) {
            try {
                cveDB.close();
            } catch (Exception ignore) {
                Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINEST, "Error closing the cveDB", ignore);
            }
        }
        if (cpeIndex != null) {
            try {
                cpeIndex.close();
            } catch (Exception ignore) {
                Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINEST, "Error closing the cpeIndex", ignore);
            }
        }
    }

    /**
     * Opens the CVE and CPE data stores.
     *
     * @throws UpdateException thrown if a data store cannot be opened
     */
    private void openDataStores() throws UpdateException {
        //open the cve and cpe data stores
        try {
            cveDB = new CveDB();
            cveDB.open();
            cpeIndex = new CpeIndexWriter();
            cpeIndex.open();
        } catch (IOException ex) {
            closeDataStores();
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINE, "IO Error opening databases", ex);
            throw new UpdateException("Error updating the CPE/CVE data, please see the log file for more details.");
        } catch (SQLException ex) {
            closeDataStores();
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINE, "SQL Exception opening databases", ex);
            throw new UpdateException("Error updating the CPE/CVE data, please see the log file for more details.");
        } catch (DatabaseException ex) {
            closeDataStores();
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINE, "Database Exception opening databases", ex);
            throw new UpdateException("Error updating the CPE/CVE data, please see the log file for more details.");
        } catch (ClassNotFoundException ex) {
            closeDataStores();
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINE, "Class not found exception opening databases", ex);
            throw new UpdateException("Error updating the CPE/CVE data, please see the log file for more details.");
        }
    }

    /**
     * Determines if the index needs to be updated. This is done by fetching the
     * NVD CVE meta data and checking the last update date. If the data needs to
     * be refreshed this method will return the NvdCveUrl for the files that
     * need to be updated.
     *
     * @return the NvdCveUrl of the files that need to be updated.
     * @throws MalformedURLException is thrown if the URL for the NVD CVE Meta
     * data is incorrect.
     * @throws DownloadFailedException is thrown if there is an error.
     * downloading the NVD CVE download data file.
     * @throws UpdateException Is thrown if there is an issue with the last
     * updated properties file.
     */
    private Map<String, NvdCveInfo> updateNeeded() throws MalformedURLException, DownloadFailedException, UpdateException {

        Map<String, NvdCveInfo> currentlyPublished;
        try {
            currentlyPublished = retrieveCurrentTimestampsFromWeb();
        } catch (InvalidDataException ex) {
            final String msg = "Unable to retrieve valid timestamp from nvd cve downloads page";
            Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINE, msg, ex);
            throw new DownloadFailedException(msg, ex);
        } catch (InvalidSettingException ex) {
            Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINE, "Invalid setting found when retrieving timestamps", ex);
            throw new DownloadFailedException("Invalid settings", ex);
        }

        if (currentlyPublished == null) {
            //TODO change messages once we have a new batch mode
            throw new DownloadFailedException("Unable to retrieve valid timestamp from NVD CVE data feeds");
        }

        final File cpeDataDirectory;
        try {
            cpeDataDirectory = CveDB.getDataDirectory();
        } catch (IOException ex) {
            String msg;
            try {
                msg = String.format("Unable to create the CVE Data Directory '%s'",
                        Settings.getFile(Settings.KEYS.CVE_DATA_DIRECTORY).getCanonicalPath());
            } catch (IOException ex1) {
                msg = String.format("Unable to create the CVE Data Directory, this is likely a configuration issue: '%s%s%s'",
                        Settings.getString(Settings.KEYS.DATA_DIRECTORY, ""),
                        File.separator,
                        Settings.getString(Settings.KEYS.CVE_DATA_DIRECTORY, ""));
            }
            throw new UpdateException(msg, ex);
        }

        if (!properties.isEmpty()) {
            try {
                boolean deleteAndRecreate = false;
                float version;

                if (properties.getProperty("version") == null) {
                    deleteAndRecreate = true;
                } else {
                    try {
                        version = Float.parseFloat(properties.getProperty("version"));
                        final float currentVersion = Float.parseFloat(CveDB.DB_SCHEMA_VERSION);
                        if (currentVersion > version) {
                            deleteAndRecreate = true;
                        }
                    } catch (NumberFormatException ex) {
                        deleteAndRecreate = true;
                    }
                }
                if (deleteAndRecreate) {
                    setDoBatchUpdate(properties.isBatchUpdateMode());
                    return currentlyPublished;
                }

                final long lastUpdated = Long.parseLong(properties.getProperty(DataStoreMetaInfo.LAST_UPDATED, "0"));
                final Date now = new Date();
                final int days = Settings.getInt(Settings.KEYS.CVE_MODIFIED_VALID_FOR_DAYS, 7);
                final int start = Settings.getInt(Settings.KEYS.CVE_START_YEAR, 2002);
                final int end = Calendar.getInstance().get(Calendar.YEAR);
                if (lastUpdated == currentlyPublished.get(MODIFIED).getTimestamp()) {
                    currentlyPublished.clear(); //we don't need to update anything.
                    setDoBatchUpdate(properties.isBatchUpdateMode());
                } else if (withinRange(lastUpdated, now.getTime(), days)) {
                    currentlyPublished.get(MODIFIED).setNeedsUpdate(true);
                    if (properties.isBatchUpdateMode()) {
                        setDoBatchUpdate(false);
                    } else {
                        for (int i = start; i <= end; i++) {
                            currentlyPublished.get(String.valueOf(i)).setNeedsUpdate(false);
                        }
                    }
                } else if (properties.isBatchUpdateMode()) {
                    currentlyPublished.get(MODIFIED).setNeedsUpdate(true);
                    setDoBatchUpdate(true);
                } else { //we figure out which of the several XML files need to be downloaded.
                    currentlyPublished.get(MODIFIED).setNeedsUpdate(false);
                    for (int i = start; i <= end; i++) {
                        final NvdCveInfo cve = currentlyPublished.get(String.valueOf(i));
                        long currentTimestamp = 0;
                        try {
                            currentTimestamp = Long.parseLong(properties.getProperty(DataStoreMetaInfo.LAST_UPDATED_BASE + String.valueOf(i), "0"));
                        } catch (NumberFormatException ex) {
                            final String msg = String.format("Error parsing '%s' '%s' from nvdcve.lastupdated",
                                    DataStoreMetaInfo.LAST_UPDATED_BASE, String.valueOf(i));
                            Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINE, msg, ex);
                        }
                        if (currentTimestamp == cve.getTimestamp()) {
                            cve.setNeedsUpdate(false); //they default to true.
                        }
                    }
                }
            } catch (NumberFormatException ex) {
                Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.WARNING, "An invalid schema version or timestamp exists in the data.properties file.");
                Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINE, null, ex);
                setDoBatchUpdate(properties.isBatchUpdateMode());
            }
        } else {
            setDoBatchUpdate(properties.isBatchUpdateMode());
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
    protected Map<String, NvdCveInfo> retrieveCurrentTimestampsFromWeb()
            throws MalformedURLException, DownloadFailedException, InvalidDataException, InvalidSettingException {

        final Map<String, NvdCveInfo> map = new TreeMap<String, NvdCveInfo>();
        String retrieveUrl = Settings.getString(Settings.KEYS.CVE_MODIFIED_20_URL);

        NvdCveInfo item = new NvdCveInfo();
        item.setNeedsUpdate(false); //the others default to true, to make life easier later this should default to false.
        item.setId(MODIFIED);
        item.setUrl(retrieveUrl);
        item.setOldSchemaVersionUrl(Settings.getString(Settings.KEYS.CVE_MODIFIED_12_URL));

        item.setTimestamp(Downloader.getLastModified(new URL(retrieveUrl)));
        map.put(MODIFIED, item);

        //only add these urls if we are not in batch mode
        if (!properties.isBatchUpdateMode()) {
            final int start = Settings.getInt(Settings.KEYS.CVE_START_YEAR);
            final int end = Calendar.getInstance().get(Calendar.YEAR);
            final String baseUrl20 = Settings.getString(Settings.KEYS.CVE_SCHEMA_2_0);
            final String baseUrl12 = Settings.getString(Settings.KEYS.CVE_SCHEMA_1_2);
            for (int i = start; i <= end; i++) {
                retrieveUrl = String.format(baseUrl20, i);
                item = new NvdCveInfo();
                item.setId(Integer.toString(i));
                item.setUrl(retrieveUrl);
                item.setOldSchemaVersionUrl(String.format(baseUrl12, i));
                item.setTimestamp(Downloader.getLastModified(new URL(retrieveUrl)));
                map.put(item.getId(), item);
            }
        }
        return map;
    }
}
