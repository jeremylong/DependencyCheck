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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.data.UpdateException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class DataStoreMetaInfo {

    /**
     * Batch key word, used as key to store information about batch mode.
     */
    public static final String BATCH = "batch";
    /**
     * Modified key word, used as a key to store information about the modified
     * file (i.e. the containing the last 8 days of updates)..
     */
    public static final String MODIFIED = "modified";
    /**
     * The name of the properties file containing the timestamp of the last
     * update.
     */
    private static final String UPDATE_PROPERTIES_FILE = "data.properties";
    /**
     * The properties file key for the last updated field - used to store the
     * last updated time of the Modified NVD CVE xml file.
     */
    public static final String LAST_UPDATED = "lastupdated.modified";
    /**
     * Stores the last updated time for each of the NVD CVE files. These
     * timestamps should be updated if we process the modified file within 7
     * days of the last update.
     */
    public static final String LAST_UPDATED_BASE = "lastupdated.";
    /**
     * A collection of properties about the data.
     */
    private Properties properties = new Properties();
    /**
     * Indicates whether or not the updates are using a batch update mode or
     * not.
     */
    private boolean batchUpdateMode;

    /**
     * Get the value of batchUpdateMode.
     *
     * @return the value of batchUpdateMode
     */
    protected boolean isBatchUpdateMode() {
        return batchUpdateMode;
    }

    /**
     * Set the value of batchUpdateMode.
     *
     * @param batchUpdateMode new value of batchUpdateMode
     */
    protected void setBatchUpdateMode(boolean batchUpdateMode) {
        this.batchUpdateMode = batchUpdateMode;
    }

    /**
     * Constructs a new data properties object.
     */
    public DataStoreMetaInfo() {
        batchUpdateMode = !Settings.getString(Settings.KEYS.BATCH_UPDATE_URL, "").isEmpty();
        loadProperties();
    }

    /**
     * Loads the data's meta properties.
     */
    private void loadProperties() {
        final File file = getPropertiesFile();
        if (file.exists()) {
            InputStream is = null;
            try {
                is = new FileInputStream(file);
            } catch (FileNotFoundException ignore) {
                //we will never get here as we check for existence above.
                Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINEST, null, ignore);
            }
            try {
                properties.load(is);
            } catch (IOException ex) {
                final String msg = String.format("Unable to load properties file '%s'", file.getPath());
                Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINE, null, ex);
            } finally {
                if (is != null) {
                    try {
                        is.close();
                    } catch (IOException ex) {
                        final String msg = String.format("Unable to close properties file '%s'", file.getPath());
                        Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.WARNING, msg);
                        Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINE, null, ex);
                    }
                }
            }
        }
    }

    /**
     * Returns whether or not any properties are set.
     *
     * @return whether or not any properties are set
     */
    public boolean isEmpty() {
        return properties.isEmpty();
    }

    /**
     * Writes a properties file containing the last updated date to the
     * VULNERABLE_CPE directory.
     *
     * @param updatedValue the updated nvdcve entry
     * @throws UpdateException is thrown if there is an update exception
     */
    public void save(NvdCveInfo updatedValue) throws UpdateException {
        if (updatedValue == null) {
            return;
        }
        final File cveProp = getPropertiesFile();
        final Properties prop = new Properties();
        if (cveProp.exists()) {
            FileInputStream in = null;
            try {
                in = new FileInputStream(cveProp);
                prop.load(in);
            } catch (Exception ignoreMe) {
                Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINEST, null, ignoreMe);
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (Exception ignoreMeToo) {
                        Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINEST, null, ignoreMeToo);
                    }
                }
            }
        }
        prop.put("version", CveDB.DB_SCHEMA_VERSION);
        prop.put(LAST_UPDATED_BASE + updatedValue.getId(), String.valueOf(updatedValue.getTimestamp()));

        OutputStream os = null;
        OutputStreamWriter out = null;
        try {
            os = new FileOutputStream(cveProp);
            out = new OutputStreamWriter(os, "UTF-8");
            prop.store(out, "Meta data about data and data sources used by dependency-check");
        } catch (FileNotFoundException ex) {
            Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINE, null, ex);
            throw new UpdateException("Unable to find last updated properties file.", ex);
        } catch (IOException ex) {
            Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINE, null, ex);
            throw new UpdateException("Unable to update last updated properties file.", ex);
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ex) {
                    Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINEST, null, ex);
                }
            }
            if (os != null) {
                try {
                    os.close();
                } catch (IOException ex) {
                    Logger.getLogger(DataStoreMetaInfo.class.getName()).log(Level.FINEST, null, ex);
                }
            }
        }
    }

    /**
     * Returns the property value for the given key. If the key is not contained
     * in the underlying properties null is returned.
     *
     * @param key the property key
     * @return the value of the property
     */
    public String getProperty(String key) {
        return properties.getProperty(key);
    }

    /**
     * Returns the property value for the given key. If the key is not contained
     * in the underlying properties the default value is returned.
     *
     * @param key the property key
     * @param defaultValue the default value
     * @return the value of the property
     */
    public String getProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }

    /**
     * Retrieves the properties file.
     *
     * @return the properties file
     */
    public static File getPropertiesFile() {
        final File dataDirectory = Settings.getDataFile(Settings.KEYS.DATA_DIRECTORY);
        final File file = new File(dataDirectory, UPDATE_PROPERTIES_FILE);
        return file;
    }
}
