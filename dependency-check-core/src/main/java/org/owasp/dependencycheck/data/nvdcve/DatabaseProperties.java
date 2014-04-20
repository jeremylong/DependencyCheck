/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.owasp.dependencycheck.data.update.NvdCveInfo;
import org.owasp.dependencycheck.data.update.exception.UpdateException;

/**
 * This is a wrapper around a set of properties that are stored in the database.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DatabaseProperties {
    
    /**
     * The Logger.
     */
    private static final Logger LOGGER = Logger.getLogger(DatabaseProperties.class.getName());
    /**
     * Modified key word, used as a key to store information about the modified file (i.e. the containing the last 8
     * days of updates)..
     */
    public static final String MODIFIED = "Modified";
    /**
     * The properties file key for the last updated field - used to store the last updated time of the Modified NVD CVE
     * xml file.
     */
    public static final String LAST_UPDATED = "NVD CVE Modified";
    /**
     * Stores the last updated time for each of the NVD CVE files. These timestamps should be updated if we process the
     * modified file within 7 days of the last update.
     */
    public static final String LAST_UPDATED_BASE = "NVD CVE ";
    /**
     * A collection of properties about the data.
     */
    private Properties properties;
    /**
     * A reference to the database.
     */
    private CveDB cveDB;

    /**
     * Constructs a new data properties object.
     *
     * @param cveDB the database object holding the properties
     */
    DatabaseProperties(CveDB cveDB) {
        this.cveDB = cveDB;
        loadProperties();
    }

    /**
     * Loads the properties from the database.
     */
    private void loadProperties() {
        this.properties = cveDB.getProperties();
    }

    /**
     * Returns whether or not any properties are set.
     *
     * @return whether or not any properties are set
     */
    public boolean isEmpty() {
        return properties == null || properties.isEmpty();
    }

    /**
     * Writes a properties file containing the last updated date to the VULNERABLE_CPE directory.
     *
     * @param updatedValue the updated NVD CVE entry
     * @throws UpdateException is thrown if there is an update exception
     */
    public void save(NvdCveInfo updatedValue) throws UpdateException {
        if (updatedValue == null) {
            return;
        }
        properties.put(LAST_UPDATED_BASE + updatedValue.getId(), String.valueOf(updatedValue.getTimestamp()));
        cveDB.saveProperty(LAST_UPDATED_BASE + updatedValue.getId(), String.valueOf(updatedValue.getTimestamp()));
    }

    /**
     * Returns the property value for the given key. If the key is not contained in the underlying properties null is
     * returned.
     *
     * @param key the property key
     * @return the value of the property
     */
    public String getProperty(String key) {
        return properties.getProperty(key);
    }

    /**
     * Returns the property value for the given key. If the key is not contained in the underlying properties the
     * default value is returned.
     *
     * @param key the property key
     * @param defaultValue the default value
     * @return the value of the property
     */
    public String getProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }

    /**
     * Returns the collection of Database Properties as a properties collection.
     *
     * @return the collection of Database Properties
     */
    public Properties getProperties() {
        return properties;
    }

    /**
     * Returns a map of the meta data from the database properties. This primarily contains timestamps of when the NVD
     * CVE information was last updated.
     *
     * @return a map of the database meta data
     */
    public Map getMetaData() {
        final TreeMap map = new TreeMap();
        for (Entry<Object, Object> entry : properties.entrySet()) {
            final String key = (String) entry.getKey();
            if (!"version".equals(key)) {
                if (key.startsWith("NVD CVE ")) {
                    try {
                        final long epoch = Long.parseLong((String) entry.getValue());
                        final Date date = new Date(epoch);
                        final DateFormat format = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
                        final String formatted = format.format(date);
                        map.put(key, formatted);
                    } catch (Throwable ex) { //deliberatly being broad in this catch clause
                        LOGGER.log(Level.FINE, "Unable to parse timestamp from DB", ex);
                        map.put(key, entry.getValue());
                    }
                } else {
                    map.put(key, entry.getValue());
                }
            }
        }
        return map;
    }
}
