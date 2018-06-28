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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.io.IOUtils;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.URLConnectionFactory;
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
     * The property key indicating when the last update occurred.
     */
    public static final String RETIREJS_UPDATED_ON = "RetireJSUpdatedOn";
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
     * @throws UpdateException thrown if the update failed
     */
    @Override
    public void update(Engine engine) throws UpdateException {
        this.settings = engine.getSettings();
        String url = null;
        try {
            final boolean autoupdate = settings.getBoolean(Settings.KEYS.AUTO_UPDATE, true);
            final boolean enabled = settings.getBoolean(Settings.KEYS.ANALYZER_RETIREJS_ENABLED, true);
            final File repoFile = new File(settings.getDataDirectory(), "jsrepository.json");
            final boolean proceed = enabled && autoupdate && shouldUpdagte(repoFile);
            if (proceed) {
                LOGGER.debug("Begin RetireJS Update");
                url = settings.getString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, DEFAULT_JS_URL);
                initializeRetireJsRepo(settings, new URL(url));
            }
        } catch (InvalidSettingException ex) {
            throw new UpdateException("Unable to determine if autoupdate is enabled", ex);
        } catch (MalformedURLException ex) {
            throw new UpdateException(String.format("Inavlid URL for RetireJS repository (%s)", url), ex);
        } catch (IOException ex) {
            throw new UpdateException("Unable to get the data directory", ex);
        }
    }

    /**
     * Determines if the we should update the RetireJS database.
     *
     * @param repo the retire JS repository.
     * @return <code>true</code> if an updated to the RetireJS database should
     * be performed; otherwise <code>false</code>
     * @throws NumberFormatException thrown if an invalid value is contained in
     * the database properties
     */
    protected boolean shouldUpdagte(File repo) throws NumberFormatException {
        boolean proceed = true;
        if (repo != null && repo.isFile()) {
            final int validForHours = settings.getInt(Settings.KEYS.ANALYZER_RETIREJS_REPO_VALID_FOR_HOURS, 0);
            final long lastUpdatedOn = repo.lastModified();
            final long now = System.currentTimeMillis();
            LOGGER.debug("Last updated: {}", lastUpdatedOn);
            LOGGER.debug("Now: {}", now);
            final long msValid = validForHours * 60L * 60L * 1000L;
            proceed = (now - lastUpdatedOn) > msValid;
            if (!proceed) {
                LOGGER.info("Skipping RetireJS update since last update was within {} hours.", validForHours);
            }
        }
        return proceed;
    }

    /**
     * Initializes the local RetireJS repository
     *
     * @param settings a reference to the dependency-check settings
     * @param repoUrl the URL to the RetireJS repo to use
     * @throws UpdateException thrown if there is an exception during
     * initialization
     */
    private void initializeRetireJsRepo(Settings settings, URL repoUrl) throws UpdateException {
        try {
            final File dataDir = settings.getDataDirectory();
            final File tmpDir = settings.getTempDirectory();
            boolean useProxy = false;
            if (null != settings.getString(Settings.KEYS.PROXY_SERVER)) {
                useProxy = true;
                LOGGER.debug("Using proxy");
            }
            LOGGER.debug("RetireJS Repo URL: {}", repoUrl.toExternalForm());
            final URLConnectionFactory factory = new URLConnectionFactory(settings);
            final HttpURLConnection conn = factory.createHttpURLConnection(repoUrl, useProxy);
            final String filename = repoUrl.getFile().substring(repoUrl.getFile().lastIndexOf("/") + 1, repoUrl.getFile().length());
            if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                final File tmpFile = new File(tmpDir, filename);
                final File repoFile = new File(dataDir, filename);
                try (InputStream inputStream = conn.getInputStream();
                        FileOutputStream outputStream = new FileOutputStream(tmpFile)) {
                    IOUtils.copy(inputStream, outputStream);
                }
                Files.move(tmpFile.toPath(), repoFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            }
        } catch (IOException e) {
            throw new UpdateException("Failed to initialize the RetireJS repo", e);
        }
    }
}
