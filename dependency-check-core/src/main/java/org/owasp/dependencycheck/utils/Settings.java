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
package org.owasp.dependencycheck.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A simple settings container that wraps the dependencycheck.properties file.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class Settings {

    /**
     * The collection of keys used within the properties file.
     */
    public static final class KEYS {

        /**
         * private constructor because this is a "utility" class containing
         * constants
         */
        private KEYS() {
            //do nothing
        }
        /**
         * The properties key indicating whether or not the cached data sources
         * should be updated.
         */
        public static final String AUTO_UPDATE = "autoupdate";
        /**
         * The database driver class name. If this is not in the properties file
         * the embedded database is used.
         */
        public static final String DB_DRIVER_NAME = "data.driver_name";
        /**
         * The database driver class name. If this is not in the properties file
         * the embedded database is used.
         */
        public static final String DB_DRIVER_PATH = "data.driver_path";
        /**
         * The database connection string. If this is not in the properties file
         * the embedded database is used.
         */
        public static final String DB_CONNECTION_STRING = "data.connection_string";
        /**
         * The username to use when connecting to the database.
         */
        public static final String DB_USER = "data.user";
        /**
         * The password to authenticate to the database.
         */
        public static final String DB_PASSWORD = "data.password";
        /**
         * The base path to use for the data directory (for embedded db).
         */
        public static final String DATA_DIRECTORY = "data.directory";
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
        public static final String CVE_START_YEAR = "cve.startyear";
        /**
         * The properties key for the CVE schema version 1.2.
         */
        public static final String CVE_SCHEMA_1_2 = "cve.url-1.2.base";
        /**
         * The properties key for the CVE schema version 2.0.
         */
        public static final String CVE_SCHEMA_2_0 = "cve.url-2.0.base";
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
         * The properties key for the proxy username.
         */
        public static final String PROXY_USERNAME = "proxy.username";
        /**
         * The properties key for the proxy password.
         */
        public static final String PROXY_PASSWORD = "proxy.password";
        /**
         * The properties key for the connection timeout.
         */
        public static final String CONNECTION_TIMEOUT = "connection.timeout";
        /**
         * The location of the temporary directory.
         */
        public static final String TEMP_DIRECTORY = "temp.directory";
        /**
         * The maximum number of threads to allocate when downloading files.
         */
        public static final String MAX_DOWNLOAD_THREAD_POOL_SIZE = "max.download.threads";
        /**
         * The key for a list of suppression files.
         */
        public static final String SUPPRESSION_FILE = "suppression.file";
        /**
         * The properties key for whether the Nexus analyzer is enabled.
         */
        public static final String ANALYZER_NEXUS_ENABLED = "analyzer.nexus.enabled";
        /**
         * The properties key for the Nexus search URL.
         */
        public static final String ANALYZER_NEXUS_URL = "analyzer.nexus.url";
    }
    /**
     * The properties file location.
     */
    private static final String PROPERTIES_FILE = "dependencycheck.properties";
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
        InputStream in = null;
        props = new Properties();
        try {
            in = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE);
            props.load(in);
        } catch (IOException ex) {
            Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, "Unable to load default settings.");
            Logger.getLogger(Settings.class.getName()).log(Level.FINE, null, ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    Logger.getLogger(Settings.class.getName()).log(Level.FINEST, null, ex);
                }
            }
        }
    }

    /**
     * Sets a property value.
     *
     * @param key the key for the property
     * @param value the value for the property
     */
    public static void setString(String key, String value) {
        INSTANCE.props.setProperty(key, value);
    }

    /**
     * Sets a property value.
     *
     * @param key the key for the property
     * @param value the value for the property
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
     * non-existent file
     * @throws IOException is thrown when there is an exception loading/merging
     * the properties
     */
    public static void mergeProperties(File filePath) throws FileNotFoundException, IOException {
        final FileInputStream fis = new FileInputStream(filePath);
        mergeProperties(fis);
    }

    /**
     * Merges a new properties file into the current properties. This method
     * allows for the loading of a user provided properties file.<br/><br/>
     * Note: even if using this method - system properties will be loaded before
     * properties loaded from files.
     *
     * @param filePath the path to the properties file to merge.
     * @throws FileNotFoundException is thrown when the filePath points to a
     * non-existent file
     * @throws IOException is thrown when there is an exception loading/merging
     * the properties
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
     * @param stream an Input Stream pointing at a properties file to merge
     * @throws IOException is thrown when there is an exception loading/merging
     * the properties
     */
    public static void mergeProperties(InputStream stream) throws IOException {
        INSTANCE.props.load(stream);
    }

    /**
     * Returns a value from the properties file as a File object. If the value
     * was specified as a system property or passed in via the -Dprop=value
     * argument - this method will return the value from the system properties
     * before the values in the contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file converted to a File object
     */
    public static File getFile(String key) {
        final String file = getString(key);
        if (file == null) {
            return null;
        }
        return new File(file);
    }

    /**
     * Returns a value from the properties file as a File object. If the value
     * was specified as a system property or passed in via the -Dprop=value
     * argument - this method will return the value from the system properties
     * before the values in the contained configuration file.
     *
     * This method will check the configured base directory and will use this as
     * the base of the file path. Additionally, if the base directory begins
     * with a leading "[JAR]\" sequence with the path to the folder containing
     * the JAR file containing this class.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file converted to a File object
     */
    public static File getDataFile(String key) {
        final String file = getString(key);
        if (file == null) {
            return null;
        }
        if (file.startsWith("[JAR]/")) {
            final File jarPath = getJarPath();
            final File newBase = new File(jarPath, file.substring(6));
            return new File(newBase, file);
        }
        return new File(file);
    }

    /**
     * Attempts to retrieve the folder containing the Jar file containing the
     * Settings class.
     *
     * @return a File object
     */
    private static File getJarPath() {
        final String jarPath = Settings.class.getProtectionDomain().getCodeSource().getLocation().getPath();
        String decodedPath = ".";
        try {
            decodedPath = URLDecoder.decode(jarPath, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Settings.class.getName()).log(Level.FINEST, null, ex);
        }

        final File path = new File(decodedPath);
        if (path.getName().toLowerCase().endsWith(".jar")) {
            return path.getParentFile();
        } else {
            return new File(".");
        }
    }

    /**
     * Returns a value from the properties file. If the value was specified as a
     * system property or passed in via the -Dprop=value argument - this method
     * will return the value from the system properties before the values in the
     * contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @param defaultValue the default value for the requested property
     * @return the property from the properties file
     */
    public static String getString(String key, String defaultValue) {
        final String str = System.getProperty(key, INSTANCE.props.getProperty(key, defaultValue));
        return str;
    }

    /**
     * Returns the temporary directory.
     *
     * @return the temporary directory
     */
    public static File getTempDirectory() {
        return new File(Settings.getString(Settings.KEYS.TEMP_DIRECTORY, System.getProperty("java.io.tmpdir")));
    }

    /**
     * Returns a value from the properties file. If the value was specified as a
     * system property or passed in via the -Dprop=value argument - this method
     * will return the value from the system properties before the values in the
     * contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file
     */
    public static String getString(String key) {
        return System.getProperty(key, INSTANCE.props.getProperty(key));
    }

    /**
     * Removes a property from the local properties collection. This is mainly
     * used in test cases.
     *
     * @param key the property key to remove
     */
    public static void removeProperty(String key) {
        INSTANCE.props.remove(key);
    }

    /**
     * Returns an int value from the properties file. If the value was specified
     * as a system property or passed in via the -Dprop=value argument - this
     * method will return the value from the system properties before the values
     * in the contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file
     * @throws InvalidSettingException is thrown if there is an error retrieving
     * the setting
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
     * Returns an int value from the properties file. If the value was specified
     * as a system property or passed in via the -Dprop=value argument - this
     * method will return the value from the system properties before the values
     * in the contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @param defaultValue the default value to return
     * @return the property from the properties file or the defaultValue if the
     * property does not exist or cannot be converted to an integer
     */
    public static int getInt(String key, int defaultValue) {
        int value;
        try {
            value = Integer.parseInt(Settings.getString(key));
        } catch (NumberFormatException ex) {
            final String msg = String.format("Could not convert property '%s' to an int.", key);
            Logger.getLogger(Settings.class.getName()).log(Level.FINEST, msg, ex);
            value = defaultValue;
        }
        return value;
    }

    /**
     * Returns a long value from the properties file. If the value was specified
     * as a system property or passed in via the -Dprop=value argument - this
     * method will return the value from the system properties before the values
     * in the contained configuration file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file
     * @throws InvalidSettingException is thrown if there is an error retrieving
     * the setting
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
     * specified as a system property or passed in via the
     * <code>-Dprop=value</code> argument this method will return the value from
     * the system properties before the values in the contained configuration
     * file.
     *
     * @param key the key to lookup within the properties file
     * @return the property from the properties file
     * @throws InvalidSettingException is thrown if there is an error retrieving
     * the setting
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
