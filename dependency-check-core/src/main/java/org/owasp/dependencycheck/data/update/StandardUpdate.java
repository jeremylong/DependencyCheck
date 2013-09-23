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

import org.owasp.dependencycheck.data.nvdcve.InvalidDataException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.data.UpdateException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import static org.owasp.dependencycheck.data.update.DataStoreMetaInfo.MODIFIED;

/**
 * Class responsible for updating the CPE and NVDCVE data stores.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class StandardUpdate extends AbstractUpdate {

    public StandardUpdate() throws MalformedURLException, DownloadFailedException, UpdateException {
        super();
    }

    /**
     * <p>Downloads the latest NVD CVE XML file from the web and imports it into
     * the current CVE Database.</p>
     *
     * @param updatesNeeded a collection of NvdCveInfo containing information
     * about needed updates.
     * @throws UpdateException is thrown if there is an error updating the
     * database
     */
    @Override
    public void update() throws UpdateException {
        try {
            properties = new DataStoreMetaInfo();
            int maxUpdates = 0;
            for (NvdCveInfo cve : updatesNeeded) {
                if (cve.getNeedsUpdate()) {
                    maxUpdates += 1;
                }
            }
            if (maxUpdates > 3) {
                Logger.getLogger(StandardUpdate.class.getName()).log(Level.INFO,
                        "NVD CVE requires several updates; this could take a couple of minutes.");
            }
            if (maxUpdates > 0) {
                openDataStores();
            }

            int count = 0;
            for (NvdCveInfo cve : updatesNeeded) {
                if (cve.getNeedsUpdate()) {
                    count += 1;
                    Logger.getLogger(StandardUpdate.class.getName()).log(Level.INFO,
                            "Updating NVD CVE ({0} of {1})", new Object[]{count, maxUpdates});
                    URL url = new URL(cve.getUrl());
                    File outputPath = null;
                    File outputPath12 = null;
                    try {
                        Logger.getLogger(StandardUpdate.class.getName()).log(Level.INFO,
                                "Downloading {0}", cve.getUrl());
                        outputPath = File.createTempFile("cve" + cve.getId() + "_", ".xml");
                        Downloader.fetchFile(url, outputPath);

                        url = new URL(cve.getOldSchemaVersionUrl());
                        outputPath12 = File.createTempFile("cve_1_2_" + cve.getId() + "_", ".xml");
                        Downloader.fetchFile(url, outputPath12);

                        Logger.getLogger(StandardUpdate.class.getName()).log(Level.INFO,
                                "Processing {0}", cve.getUrl());

                        importXML(outputPath, outputPath12);

                        cveDB.commit();
                        cpeIndex.commit();

                        properties.save(cve);

                        Logger.getLogger(StandardUpdate.class.getName()).log(Level.INFO,
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
            if (maxUpdates >= 1) { //ensure the modified file date gets written
                properties.save(updatesNeeded.get(MODIFIED));
                cveDB.cleanupDatabase();
            }
        } catch (MalformedURLException ex) {
            throw new UpdateException(ex);
        } finally {
            closeDataStores();
        }
    }

    /**
     * Determines if the index needs to be updated. This is done by fetching the
     * NVD CVE meta data and checking the last update date. If the data needs to
     * be refreshed this method will return the NvdCveUrl for the files that
     * need to be updated.
     *
     * @return the collection of files that need to be updated
     * @throws MalformedURLException is thrown if the URL for the NVD CVE Meta
     * data is incorrect
     * @throws DownloadFailedException is thrown if there is an error.
     * downloading the NVD CVE download data file
     * @throws UpdateException Is thrown if there is an issue with the last
     * updated properties file
     */
    @Override
    protected Updateable updatesNeeded() throws MalformedURLException, DownloadFailedException, UpdateException {
        Updateable updates = null;
        try {
            updates = retrieveCurrentTimestampsFromWeb();
        } catch (InvalidDataException ex) {
            final String msg = "Unable to retrieve valid timestamp from nvd cve downloads page";
            Logger.getLogger(StandardUpdate.class.getName()).log(Level.FINE, msg, ex);
            throw new DownloadFailedException(msg, ex);
        } catch (InvalidSettingException ex) {
            Logger.getLogger(StandardUpdate.class.getName()).log(Level.FINE, "Invalid setting found when retrieving timestamps", ex);
            throw new DownloadFailedException("Invalid settings", ex);
        }

        if (updates == null) {
            throw new DownloadFailedException("Unable to retrieve the timestamps of the currently published NVD CVE data");
        }

        if (!properties.isEmpty()) {
            try {
                float version;

                if (properties.getProperty("version") == null) {
                    setDeleteAndRecreate(true);
                } else {
                    try {
                        version = Float.parseFloat(properties.getProperty("version"));
                        final float currentVersion = Float.parseFloat(CveDB.DB_SCHEMA_VERSION);
                        if (currentVersion > version) {
                            setDeleteAndRecreate(true);
                        }
                    } catch (NumberFormatException ex) {
                        setDeleteAndRecreate(true);
                    }
                }

                if (shouldDeleteAndRecreate()) {
                    return updates;
                }

                final long lastUpdated = Long.parseLong(properties.getProperty(DataStoreMetaInfo.LAST_UPDATED, "0"));
                final Date now = new Date();
                final int days = Settings.getInt(Settings.KEYS.CVE_MODIFIED_VALID_FOR_DAYS, 7);
                final int start = Settings.getInt(Settings.KEYS.CVE_START_YEAR, 2002);
                final int end = Calendar.getInstance().get(Calendar.YEAR);
                if (lastUpdated == updates.getTimeStamp(MODIFIED)) {
                    updates.clear(); //we don't need to update anything.
                } else if (withinRange(lastUpdated, now.getTime(), days)) {
                    for (NvdCveInfo entry : updates) {
                        if (MODIFIED.equals(entry.getId())) {
                            entry.setNeedsUpdate(true);
                        } else {
                            entry.setNeedsUpdate(false);
                        }
                    }
                } else { //we figure out which of the several XML files need to be downloaded.
                    for (NvdCveInfo entry : updates) {
                        if (MODIFIED.equals(entry.getId())) {
                            entry.setNeedsUpdate(true);
                        } else {
                            long currentTimestamp = 0;
                            try {
                                currentTimestamp = Long.parseLong(properties.getProperty(DataStoreMetaInfo.LAST_UPDATED_BASE + entry.getId(), "0"));
                            } catch (NumberFormatException ex) {
                                final String msg = String.format("Error parsing '%s' '%s' from nvdcve.lastupdated",
                                        DataStoreMetaInfo.LAST_UPDATED_BASE, entry.getId());
                                Logger.getLogger(StandardUpdate.class.getName()).log(Level.FINE, msg, ex);
                            }
                            if (currentTimestamp == entry.getTimestamp()) {
                                entry.setNeedsUpdate(false);
                            }
                        }
                    }
                }
            } catch (NumberFormatException ex) {
                final String msg = "An invalid schema version or timestamp exists in the data.properties file.";
                Logger.getLogger(StandardUpdate.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(StandardUpdate.class.getName()).log(Level.FINE, null, ex);
            }
        }
        return updates;
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
    private Updateable retrieveCurrentTimestampsFromWeb()
            throws MalformedURLException, DownloadFailedException, InvalidDataException, InvalidSettingException {

        Updateable updates = new Updateable();
        updates.add(MODIFIED, Settings.getString(Settings.KEYS.CVE_MODIFIED_20_URL),
                Settings.getString(Settings.KEYS.CVE_MODIFIED_12_URL),
                false);

        //only add these urls if we are not in batch mode
        if (!properties.isBatchUpdateMode()) {
            final int start = Settings.getInt(Settings.KEYS.CVE_START_YEAR);
            final int end = Calendar.getInstance().get(Calendar.YEAR);
            final String baseUrl20 = Settings.getString(Settings.KEYS.CVE_SCHEMA_2_0);
            final String baseUrl12 = Settings.getString(Settings.KEYS.CVE_SCHEMA_1_2);
            for (int i = start; i <= end; i++) {
                updates.add(Integer.toString(i), String.format(baseUrl20, i),
                        String.format(baseUrl12, i),
                        true);
            }
        }
        return updates;
    }
}
