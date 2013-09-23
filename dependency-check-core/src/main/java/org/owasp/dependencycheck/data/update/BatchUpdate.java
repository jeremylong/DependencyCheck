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
import java.net.URISyntaxException;
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
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import static org.owasp.dependencycheck.data.update.DataStoreMetaInfo.BATCH;
import static org.owasp.dependencycheck.data.update.DataStoreMetaInfo.MODIFIED;

/**
 * Class responsible for updating the CPE and NVDCVE data stores.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class BatchUpdate extends AbstractUpdate {

    public BatchUpdate() throws MalformedURLException, DownloadFailedException, UpdateException {
        super();
    }
    /**
     * A flag indicating whether or not the batch update should be performed.
     */
    private boolean doBatchUpdate;

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
    public Updateable updatesNeeded() throws MalformedURLException, DownloadFailedException, UpdateException {
        Updateable updates = null;
        try {
            updates = retrieveCurrentTimestampsFromWeb();
        } catch (InvalidDataException ex) {
            final String msg = "Unable to retrieve valid timestamp from nvd cve downloads page";
            Logger.getLogger(BatchUpdate.class.getName()).log(Level.FINE, msg, ex);
            throw new DownloadFailedException(msg, ex);
        } catch (InvalidSettingException ex) {
            Logger.getLogger(BatchUpdate.class.getName()).log(Level.FINE, "Invalid setting found when retrieving timestamps", ex);
            throw new DownloadFailedException("Invalid settings", ex);
        }

        if (updates == null) {
            throw new DownloadFailedException("Unable to retrieve the timestamps of the currently published NVD CVE data");
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

                final NvdCveInfo batchInfo = updates.get(BATCH);
                if (properties.isBatchUpdateMode() && batchInfo != null) {
                    final long lastUpdated = Long.parseLong(properties.getProperty(DataStoreMetaInfo.BATCH, "0"));
                    if (lastUpdated != batchInfo.getTimestamp()) {
                        deleteAndRecreate = true;
                    }
                }

                if (deleteAndRecreate) {
                    setDoBatchUpdate(properties.isBatchUpdateMode());
                    try {
                        deleteExistingData();
                    } catch (IOException ex) {
                        final String msg = "Unable to delete existing data";
                        Logger.getLogger(BatchUpdate.class.getName()).log(Level.WARNING, msg);
                        Logger.getLogger(BatchUpdate.class.getName()).log(Level.FINE, null, ex);
                    }
                    return updates;
                }

                final long lastUpdated = Long.parseLong(properties.getProperty(DataStoreMetaInfo.LAST_UPDATED, "0"));
                final Date now = new Date();
                final int days = Settings.getInt(Settings.KEYS.CVE_MODIFIED_VALID_FOR_DAYS, 7);
                final int start = Settings.getInt(Settings.KEYS.CVE_START_YEAR, 2002);
                final int end = Calendar.getInstance().get(Calendar.YEAR);
                if (lastUpdated == updates.get(MODIFIED).getTimestamp()) {
                    updates.clear(); //we don't need to update anything.
                    setDoBatchUpdate(properties.isBatchUpdateMode());
                } else if (withinRange(lastUpdated, now.getTime(), days)) {
                    updates.get(MODIFIED).setNeedsUpdate(true);
                    if (properties.isBatchUpdateMode()) {
                        setDoBatchUpdate(false);
                    } else {
                        for (int i = start; i <= end; i++) {
                            updates.get(String.valueOf(i)).setNeedsUpdate(false);
                        }
                    }
                } else if (properties.isBatchUpdateMode()) {
                    updates.get(MODIFIED).setNeedsUpdate(true);
                    setDoBatchUpdate(true);
                } else { //we figure out which of the several XML files need to be downloaded.
                    updates.get(MODIFIED).setNeedsUpdate(false);
                    for (int i = start; i <= end; i++) {
                        final NvdCveInfo cve = updates.get(String.valueOf(i));
                        long currentTimestamp = 0;
                        try {
                            currentTimestamp = Long.parseLong(properties.getProperty(DataStoreMetaInfo.LAST_UPDATED_BASE + String.valueOf(i), "0"));
                        } catch (NumberFormatException ex) {
                            final String msg = String.format("Error parsing '%s' '%s' from nvdcve.lastupdated",
                                    DataStoreMetaInfo.LAST_UPDATED_BASE, String.valueOf(i));
                            Logger.getLogger(BatchUpdate.class.getName()).log(Level.FINE, msg, ex);
                        }
                        if (currentTimestamp == cve.getTimestamp()) {
                            cve.setNeedsUpdate(false); //they default to true.
                        }
                    }
                }
            } catch (NumberFormatException ex) {
                final String msg = "An invalid schema version or timestamp exists in the data.properties file.";
                Logger.getLogger(BatchUpdate.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(BatchUpdate.class.getName()).log(Level.FINE, null, ex);
                setDoBatchUpdate(properties.isBatchUpdateMode());
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
        updates.add(BATCH, Settings.getString(Settings.KEYS.BATCH_UPDATE_URL),
                null, false);

        String url = Settings.getString(Settings.KEYS.CVE_MODIFIED_20_URL, "");
        if (!url.isEmpty()) {
            final NvdCveInfo item = new NvdCveInfo();
            updates.add(MODIFIED, url,
                    Settings.getString(Settings.KEYS.CVE_MODIFIED_12_URL),
                    false);
        }
        return updates;
    }
}
