/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A simple settings container that wraps the dependencycheck.properties file.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public final class Settings {

    /**
     * The collection of keys used within the properties file.
     */
    public static final class KEYS {

        /**
         * private constructor because this is a "utility" class containing constants
         */
        private KEYS() {
            //do nothing
        }

        /**
         * The properties key for the path where the CPE Lucene Index will be
         * stored.
         */
        public static final String CPE_INDEX = "cpe";
        /**
         * The properties key for the URL to the CPE.
         */
        public static final String CPE_URL = "cpe.url";
        /**
         * The properties key for the URL to the CPE.
         */
        public static final String CPE_META_URL = "cpe.meta.url";
        /**
         * The properties key for the path where the CVE Lucene Index will be
         * stored.
         */
        public static final String CVE_INDEX = "cve";
        /**
         * The properties key for the URL to retrieve the "meta" data from about
         * the CVE entries.
         */
        public static final String CVE_META_URL = "cve.url.meta";
        /**
         * The properties key for the URL to retrieve the recently modified and
         * added CVE entries (last 8 days) using the 2.0 schema.
         */
        public static final String CVE_MODIFIED_20_URL = "cve.url-2.0.modified";
        /**
         * The properties key for the URL to retrieve the recently modified and
         * added CVE entries (last 8 days) using the 1.2 schema.
         */
        public static final String CVE_MODIFIED_12_URL = "cve.url-1.2.modified";
        /**
         * The properties key for the URL to retrieve the recently modified and
         * added CVE entries (last 8 days).
         */
        public static final String CVE_MODIFIED_VALID_FOR_DAYS = "cve.url.modified.validfordays";
        /**
         * The properties key for the telling us how many cvr.url.* URLs exists.
         * This is used in combination with CVE_BASE_URL to be able to retrieve
         * the URLs for all of the files that make up the NVD CVE listing.
         */
        public static final String CVE_URL_COUNT = "cve.url.count";
        /**
         * The properties key for the "base" property key for the CVE URLs (e.g.
         * cve.url-2.0.1, cve.url-1.2.2, cve.url.n).
         */
        public static final String CVE_BASE_URL = "cve.url-";
        /**
         * The properties key for the CVE schema version 1.2.
         */
        public static final String CVE_SCHEMA_1_2 = "1.2.";
        /**
         * The properties key for the CVE schema version 2.0.
         */
        public static final String CVE_SCHEMA_2_0 = "2.0.";


        /**
         * The properties key for the proxy url.
         */
        public static final String PROXY_URL = "proxy.url";
        /**
         * The properties key for the proxy port - this must be an integer
         * value.
         */
        public static final String PROXY_PORT = "proxy.port";
        /**
         * The properties key for the connection timeout.
         */
        public static final String CONNECTION_TIMEOUT = "connection.timeout";
        /**
         * The properties key indicating a deep scan should be performed.
         */
        public static final String PERFORM_DEEP_SCAN = "perform.deepscan";
    }
    /**
     * The properties file location.
     */
    private static final String PROPERTIES_FILE = "configuration/dependencycheck.properties";
    /**
     * The singleton instance variable.
     */
    private static final Settings INSTANCE = new Settings();
    /**
     * The properties.
     */
    private Properties props = null;

    /**
     * Private constructor for the Settings class. This class loads the
     * properties files.
     */
    private Settings() {
        final InputStream in = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE);
        props = new Properties();
        try {
            props.load(in);
        } catch (IOException ex) {
            Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Sets a property value.
     *
     * @param key the key for the property.
     * @param value the value for the property.
     */
    public static void setString(String key, String value) {
        INSTANCE.props.setProperty(key, value);
    }
    /**
     * Sets a property value.
     *
     * @param key the key for the property.
     * @param value the value for the property.
     */
    public static void setBoolean(String key, boolean value) {
        if (value) {
            INSTANCE.props.setProperty(key, Boolean.TRUE.toString());
        } else {
            INSTANCE.props.setProperty(key, Boolean.FALSE.toString());
        }
    }

    /**
     * Merges a new properties file into the current properties. This method
     * allows for the loading of a user provided properties file.<br/><br/>
     * Note: even if using this method - system properties will be loaded before
     * properties loaded from files.
     *
     * @param filePath the path to the properties file to merge.
     * @throws FileNotFoundException is thrown when the filePath points to a
     * non-existent file.
     * @throws IOException is thrown when there is an exception loading/merging
     * the properties.
     */
    public static void mergeProperties(String filePath) throws FileNotFoundException, IOException {
        final FileInputStream fis = new FileInputStream(filePath);
        mergeProperties(fis);
    }

    /**
     * Merges a new properties file into the current properties. This method
     * allows for the loading of a user provided properties file.<br/><br/>
     * Note: even if using this method - system properties will be loaded before
     * properties loaded from files.
     *
     * @param stream an Input Stream pointing at a properties file to merge.
     * @throws IOException is thrown when there is an exception loading/merging
     * the properties
     */
    public static void mergeProperties(InputStream stream) throws IOException {
        INSTANCE.props.load(stream);
    }

    /**
     * Returns a value from the properties file. If the value was specified as a
     * system property or passed in via the -Dprop=value argument - this method
     * will return the value from the system properties before the values in the
     * contained configuration file.
     *
     * @param key the key to lookup within the properties file.
     * @param defaultValue the default value for the requested property.
     * @return the property from the properties file.
     */
    public static String getString(String key, String defaultValue) {
        String str = System.getProperty(key, INSTANCE.props.getProperty(key));
        if (str == null) {
            str = defaultValue;
        }
        return str;
    }

    /**
     * Returns a value from the properties file. If the value was specified as a
     * system property or passed in via the -Dprop=value argument - this method
     * will return the value from the system properties before the values in the
     * contained configuration file.
     *
     * @param key the key to lookup within the properties file.
     * @return the property from the properties file.
     */
    public static String getString(String key) {
        return System.getProperty(key, INSTANCE.props.getProperty(key));
    }

    /**
     * Returns an int value from the properties file. If the value was specified
     * as a system property or passed in via the -Dprop=value argument - this
     * method will return the value from the system properties before the values
     * in the contained configuration file.
     *
     * @param key the key to lookup within the properties file.
     * @return the property from the properties file.
     * @throws InvalidSettingException is thrown if there is an error retrieving
     * the setting.
     */
    public static int getInt(String key) throws InvalidSettingException {
        int value;
        try {
            value = Integer.parseInt(Settings.getString(key));
        } catch (NumberFormatException ex) {
            throw new InvalidSettingException("Could not convert property '" + key + "' to an int.", ex);
        }
        return value;
    }

    /**
     * Returns a long value from the properties file. If the value was specified
     * as a system property or passed in via the -Dprop=value argument - this
     * method will return the value from the system properties before the values
     * in the contained configuration file.
     *
     * @param key the key to lookup within the properties file.
     * @return the property from the properties file.
     * @throws InvalidSettingException is thrown if there is an error retrieving
     * the setting.
     */
    public static long getLong(String key) throws InvalidSettingException {
        long value;
        try {
            value = Long.parseLong(Settings.getString(key));
        } catch (NumberFormatException ex) {
            throw new InvalidSettingException("Could not convert property '" + key + "' to an int.", ex);
        }
        return value;
    }

    /**
     * Returns a boolean value from the properties file. If the value was
     * specified as a system property or passed in via the -Dprop=value argument
     * - this method will return the value from the system properties before the
     * values in the contained configuration file.
     *
     * @param key the key to lookup within the properties file.
     * @return the property from the properties file.
     * @throws InvalidSettingException is thrown if there is an error retrieving
     * the setting.
     */
    public static boolean getBoolean(String key) throws InvalidSettingException {
        boolean value;
        try {
            value = Boolean.parseBoolean(Settings.getString(key));
        } catch (NumberFormatException ex) {
            throw new InvalidSettingException("Could not convert property '" + key + "' to an int.", ex);
        }
        return value;
    }
}
