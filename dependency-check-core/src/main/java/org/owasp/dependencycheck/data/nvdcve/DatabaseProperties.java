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
package org.owasp.dependencycheck.data.nvdcve;

import java.util.Properties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.data.update.NvdCveInfo;

/**
 * This is a wrapper around a set of properties that are stored in the database.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DatabaseProperties {

    /**
     * Modified key word, used as a key to store information about the modified
     * file (i.e. the containing the last 8 days of updates)..
     */
    public static final String MODIFIED = "modified";
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
     * Writes a properties file containing the last updated date to the
     * VULNERABLE_CPE directory.
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
}
