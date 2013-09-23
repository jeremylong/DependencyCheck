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

import java.io.File;
import java.io.IOException;
import org.owasp.dependencycheck.data.CachedWebDataSource;
import java.net.MalformedURLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.concurrency.DirectoryLockException;
import org.owasp.dependencycheck.concurrency.DirectorySpinLock;
import org.owasp.dependencycheck.concurrency.InvalidDirectoryException;
import org.owasp.dependencycheck.data.UpdateException;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 * Class responsible for updating the CPE and NVDCVE data stores.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class DatabaseUpdater implements CachedWebDataSource {

    /**
     * Utility to read and write meta-data about the data.
     */
    protected DataStoreMetaInfo properties = null;

    /**
     * <p>Downloads the latest NVD CVE XML file from the web and imports it into
     * the current CVE Database.</p>
     *
     * @throws UpdateException is thrown if there is an error updating the
     * database
     */
    @Override
    public void update() throws UpdateException {
        properties = new DataStoreMetaInfo();
        AbstractUpdate store = null;
        File dataDir = Settings.getFile(Settings.KEYS.DATA_DIRECTORY);
        DirectorySpinLock lock = null;
        try {
            lock = new DirectorySpinLock(dataDir);
        } catch (InvalidDirectoryException ex) {
            throw new UpdateException("Unable to obtain lock on the data directory", ex);
        } catch (DirectoryLockException ex) {
            throw new UpdateException("Unable to obtain exclusive lock on the data directory", ex);
        }

        try {
            lock.obtainSharedLock();
            if (properties.isBatchUpdateMode()) {
                store = new BatchUpdate();
            } else {
                store = new StandardUpdate();
            }
            if (store.isUpdateNeeded()) {
                lock.release();
                lock.obtainExclusiveLock();
                if (store.shouldDeleteAndRecreate()) {
                    try {
                        deleteExistingData();
                    } catch (IOException ex) {
                        Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.WARNING, "Unable to delete the existing data directory");
                        Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINE, null, ex);
                    }
                }
                store.update();
            }
        } catch (DirectoryLockException ex) {
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.WARNING,
                    "Unable to obtain lock on data directory, unable to update the data to use the most current data.");
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINE, null, ex);
        } catch (MalformedURLException ex) {
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.WARNING,
                    "NVD CVE properties files contain an invalid URL, unable to update the data to use the most current data.");
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINE, null, ex);
        } catch (DownloadFailedException ex) {
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.WARNING,
                    "Unable to download the NVD CVE data, unable to update the data to use the most current data.");
            Logger.getLogger(DatabaseUpdater.class.getName()).log(Level.FINE, null, ex);
        } finally {
            if (lock != null) {
                lock.release();
            }
        }
    }

    /**
     * Deletes the existing data directories.
     *
     * @throws IOException thrown if the directory cannot be deleted
     */
    protected void deleteExistingData() throws IOException {
        File data = Settings.getFile(Settings.KEYS.CVE_DATA_DIRECTORY);
        if (data.exists()) {
            FileUtils.delete(data);
        }
        data = Settings.getFile(Settings.KEYS.CPE_DATA_DIRECTORY);
        if (data.exists()) {
            FileUtils.delete(data);
        }
        data = DataStoreMetaInfo.getPropertiesFile();
        if (data.exists()) {
            FileUtils.delete(data);
        }
    }
}
