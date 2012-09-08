package org.codesecure.dependencycheck.utils;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A simple settings container that wraps the dependencycheck.properties file.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class Settings {


    /**
     * The collection of keys used within the properties file.
     */
    public abstract class KEYS {

        /**
         * The properties key for the path where the CPE Lucene Index will be stored.
         */
        public static final String CPE_INDEX = "cpe";
        /**
         * The properties key for the URL to the CPE.
         */
        public static final String CPE_URL = "cpe.url";
        /**
         * The properties key for the URL to the CPE.
         */
        public static final String CPE_DOWNLOAD_FREQUENCY = "cpe.downloadfrequency";
        /**
         * The properties key for the path where the CCE Lucene Index will be stored.
         */
        public static final String CVE_INDEX = "cve";
        /**
         * The properties key for the path where the OSVDB Lucene Index will be stored.
         */
        public static final String OSVDB_INDEX = "osvdb";
        /**
         * The properties key prefix for the analyzer assocations.
         */
        public static final String FILE_EXTENSION_ANALYZER_ASSOCIATION_PREFIX = "file.extension.analyzer.association.";
    }
    private static final String PROPERTIES_FILE = "dependencycheck.properties";
    private static Settings instance = new Settings();
    private Properties props = null;

    /**
     * Private contructor for the Settings class. This class loads the properties files.
     */
    private Settings() {
        InputStream in = this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_FILE);
        props = new Properties();
        try {
            props.load(in);
        } catch (IOException ex) {
            Logger.getLogger(Settings.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Returns a value from the properties file. If the value was specified as a
     * system property or passed in via the -Dprop=value argument - this method
     * will return the value from the system properties before the values in
     * the contained configuration file.
     *
     * @param key the key to lookup within the properties file.
     * @param defaultValue the default value for the requested property.
     * @return the property from the properties file.
     */
    public static String getString(String key, String defaultValue) {
        String str = System.getProperty(key, instance.props.getProperty(key));
        if (str == null) {
            str = defaultValue;
        }
        return str;
    }

    /**
     * Returns a value from the properties file. If the value was specified as a
     * system property or passed in via the -Dprop=value argument - this method
     * will return the value from the system properties before the values in
     * the contained configuration file.
     *
     * @param key the key to lookup within the properties file.
     * @return the property from the properties file.
     */
    public static String getString(String key) {
        return System.getProperty(key, instance.props.getProperty(key));
    }

    /**
     * Returns a map of properties selected by a given prefix. For isntance
     * if you have five properties that started off with "org.codesecure.name"
     * you could get a collection of those properties by calling this method.
     *
     * NOTE: The prefix is removed from the given properties when returned.
     *
     * @param prefix the prefix used to search the property collections for.
     * @return a Map of properties found.
     */
    public static Map<String, String> getPropertiesByPrefix(String prefix) {
        Map<String, String> ret = new HashMap<String, String>();

        Properties properties = instance.props;
        for (Enumeration<Object> e = properties.keys(); e.hasMoreElements(); ) {
            Object o = e.nextElement();
            if (o instanceof String) {
                String key = (String) o;
                if (key.startsWith(prefix)) {
                    String ext = key.substring(prefix.length());
                    ret.put(ext, properties.getProperty(key));
                }
            }
        }
        properties = System.getProperties();
        for (Enumeration<Object> e = properties.keys(); e.hasMoreElements(); ) {
            Object o = e.nextElement();
            if (o instanceof String) {
                String key = (String) o;
                if (key.startsWith(prefix)) {
                    String ext = key.substring(prefix.length() + 1);
                    ret.put(ext, properties.getProperty(key));
                }
            }
        }
        return ret;
    }
    /**
     * Returns a integer value from the properties file. If the value was specified as a
     * system property or passed in via the -Dprop=value argument - this method
     * will return the value from the system properties before the values in
     * the contained configuration file.
     *
     * @param key the key to lookup within the properties file.
     * @return the property from the properties file.
     */
    public static int getInt(String key) {
        return Integer.parseInt(Settings.getString(key));
    }
    /**
     * Returns a boolean value from the properties file. If the value was specified as a
     * system property or passed in via the -Dprop=value argument - this method
     * will return the value from the system properties before the values in
     * the contained configuration file.
     *
     * @param key the key to lookup within the properties file.
     * @return the property from the properties file.
     */
    public static boolean getBoolean(String key) {
        return Boolean.parseBoolean(Settings.getString(key));
    }
}
