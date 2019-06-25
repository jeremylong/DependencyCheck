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
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import javax.annotation.concurrent.ThreadSafe;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
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
     * @return returns false as no updates are made to the database that would
     * require compaction
     * @throws UpdateException thrown if the update failed
     */
    @Override
    public boolean update(Engine engine) throws UpdateException {
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
        } catch (MalformedURLException ex) {
            throw new UpdateException(String.format("Inavlid URL for RetireJS repository (%s)", url), ex);
        } catch (IOException ex) {
            throw new UpdateException("Unable to get the data directory", ex);
        }
        return false;
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

            LOGGER.debug("RetireJS Repo URL: {}", repoUrl.toExternalForm());
            final Downloader downloader = new Downloader(settings);
            final String filename = repoUrl.getFile().substring(repoUrl.getFile().lastIndexOf("/") + 1);
            final File repoFile = new File(dataDir, filename);
            downloader.fetchFile(repoUrl, repoFile);
        } catch (IOException | TooManyRequestsException | ResourceNotFoundException ex) {
            throw new UpdateException("Failed to initialize the RetireJS repo", ex);
        }
    }

    @Override
    public boolean purge(Engine engine) {
        boolean result = true;
        try {
            final File dataDir = engine.getSettings().getDataDirectory();
            final URL repoUrl = new URL(engine.getSettings().getString(Settings.KEYS.ANALYZER_RETIREJS_REPO_JS_URL, DEFAULT_JS_URL));
            final String filename = repoUrl.getFile().substring(repoUrl.getFile().lastIndexOf("/") + 1);
            final File repo = new File(dataDir, filename);
            if (repo.exists()) {
                if (repo.delete()) {
                    LOGGER.info("RetireJS repo removed successfully");
                } else {
                    LOGGER.error("Unable to delete '{}'; please delete the file manually", repo.getAbsolutePath());
                    result = false;
                }
            }
        } catch (IOException ex) {
            LOGGER.error("Unable to delete the RetireJS repo - invalid configuration");
            result = false;
        }
        return result;
    }
}
