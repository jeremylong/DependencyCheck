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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.io.IOUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.DateUtil;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
import org.owasp.dependencycheck.utils.URLConnectionFailureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Checks the gh-pages dependency-check site to determine the current released
 * version number. If the released version number is greater than the running
 * version number a warning is printed recommending that an upgrade be
 * performed.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class RetireJSDataSource implements CachedWebDataSource {

    /**
     * Static logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(RetireJSDataSource.class);
    /**
     * The property key indicating when the last version check occurred.
     */
    public static final String RETIREJS_CHECKED_ON = "RetireJSCheckedOn";
    /**
     * The configured settings.
     */
    private Settings settings;
    /**
     * The default URL to the RetireJS JavaScript repository.
     */
    private static final String DEFAULT_JS_URL = "https://raw.githubusercontent.com/Retirejs/retire.js/master/repository/jsrepository.json";

    /**
     * Constructs a new engine version check utility for testing.
     *
     * @param settings the configured settings
     */
    protected RetireJSDataSource(Settings settings) {
        this.settings = settings;
    }

    /**
     * Constructs a new engine version check utility.
     */
    public RetireJSDataSource() {
    }

    /**
     * Downloads the current RetireJS data source.
     *
     * @throws UpdateException thrown if the local database properties could not
     * be updated
     */
    @Override
    public void update(Engine engine) throws UpdateException {
        this.settings = engine.getSettings();
        try {
            final CveDB db = engine.getDatabase();
            final boolean autoupdate = settings.getBoolean(Settings.KEYS.AUTO_UPDATE, true);
            final boolean enabled = settings.getBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);

            if (enabled && autoupdate) {
                LOGGER.debug("Begin RetireJS Update");

                final DatabaseProperties properties = db.getDatabaseProperties();

                final long lastChecked = Long.parseLong(properties.getProperty(RETIREJS_CHECKED_ON, "0"));
                final long now = System.currentTimeMillis();
                LOGGER.debug("Last checked: {}", lastChecked);
                LOGGER.debug("Now: {}", now);
                
            }
        } catch (DatabaseException ex) {
            LOGGER.debug("Database Exception opening databases to retrieve properties", ex);
            throw new UpdateException("Error occurred updating database properties.");
        } catch (InvalidSettingException ex) {
            LOGGER.debug("Unable to determine if autoupdate is enabled", ex);
        }
    }

    /**
     * Retrieves the current released version number from the github
     * documentation site.
     *
     * @return the current released version number
     */
    protected String getCurrentReleaseVersion() {
        HttpURLConnection conn = null;
        try {
            final String str = settings.getString(Settings.KEYS.ENGINE_VERSION_CHECK_URL, DEFAULT_JS_URL);
            final URL url = new URL(str);
            final URLConnectionFactory factory = new URLConnectionFactory(settings);
            conn = factory.createHttpURLConnection(url);
            conn.connect();
            if (conn.getResponseCode() != 200) {
                return null;
            }
            final String releaseVersion = IOUtils.toString(conn.getInputStream(), "UTF-8");
            if (releaseVersion != null) {
                return releaseVersion.trim();
            }
        } catch (MalformedURLException ex) {
            LOGGER.debug("Unable to retrieve current release version of dependency-check - malformed url?");
        } catch (URLConnectionFailureException ex) {
            LOGGER.debug("Unable to retrieve current release version of dependency-check - connection failed");
        } catch (IOException ex) {
            LOGGER.debug("Unable to retrieve current release version of dependency-check - i/o exception");
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
        return null;
    }
}
