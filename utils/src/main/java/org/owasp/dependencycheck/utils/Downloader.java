/*
 * This file is part of dependency-check-utils.
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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import static java.lang.String.format;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A utility to download files from the Internet.
 *
 * @author Jeremy Long
 * @version $Id: $Id
 */
public final class Downloader {

    /**
     * UTF-8 character set name.
     */
    private static final String UTF8 = StandardCharsets.UTF_8.name();
    /**
     * The Logger for use throughout the class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Downloader.class);
    /**
     * The configured settings.
     */
    private final Settings settings;

    /**
     * Constructs a new Downloader object.
     *
     * @param settings the configured settings
     */
    public Downloader(Settings settings) {
        this.settings = settings;
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     *
     * @param url the URL of the file to download
     * @param outputPath the path to the save the file to
     * @throws org.owasp.dependencycheck.utils.DownloadFailedException is thrown
     * if there is an error downloading the file
     * @throws TooManyRequestsException thrown when a 429 is received
     * @throws ResourceNotFoundException thrown when a 404 is received
     */
    public void fetchFile(URL url, File outputPath) throws DownloadFailedException, TooManyRequestsException, ResourceNotFoundException {
        fetchFile(url, outputPath, true, null, null);
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     *
     * @param url the URL of the file to download
     * @param outputPath the path to the save the file to
     * @param userKey the settings key for the username to be used
     * @param passwordKey the settings key for the password to be used
     * @throws org.owasp.dependencycheck.utils.DownloadFailedException is thrown
     * if there is an error downloading the file
     * @throws TooManyRequestsException thrown when a 429 is received
     * @throws ResourceNotFoundException thrown when a 404 is received
     */
    public void fetchFile(URL url, File outputPath, String userKey, String passwordKey)
            throws DownloadFailedException, TooManyRequestsException, ResourceNotFoundException {
        fetchFile(url, outputPath, true, userKey, passwordKey);
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     *
     * @param url the URL of the file to download
     * @param outputPath the path to the save the file to
     * @param useProxy whether to use the configured proxy when downloading
     * files
     * @throws org.owasp.dependencycheck.utils.DownloadFailedException is thrown
     * if there is an error downloading the file
     * @throws TooManyRequestsException thrown when a 429 is received
     * @throws ResourceNotFoundException thrown when a 404 is received
     */
    public void fetchFile(URL url, File outputPath, boolean useProxy) throws DownloadFailedException,
            TooManyRequestsException, ResourceNotFoundException {
        fetchFile(url, outputPath, useProxy, null, null);
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     *
     * @param url the URL of the file to download
     * @param outputPath the path to the save the file to
     * @param useProxy whether to use the configured proxy when downloading
     * files
     * @param userKey the settings key for the username to be used
     * @param passwordKey the settings key for the password to be used
     * @throws org.owasp.dependencycheck.utils.DownloadFailedException is thrown
     * if there is an error downloading the file
     * @throws TooManyRequestsException thrown when a 429 is received
     * @throws ResourceNotFoundException thrown when a 404 is received
     */
    public void fetchFile(URL url, File outputPath, boolean useProxy, String userKey, String passwordKey) throws DownloadFailedException,
            TooManyRequestsException, ResourceNotFoundException {
        InputStream in = null;
        try (HttpResourceConnection conn = new HttpResourceConnection(settings, useProxy, userKey, passwordKey);
                OutputStream out = new FileOutputStream(outputPath)) {
            in = conn.fetch(url);
            IOUtils.copy(in, out);
        } catch (IOException ex) {
            final String msg = format("Download failed, unable to copy '%s' to '%s'; %s",
                    url.toString(), outputPath.getAbsolutePath(), ex.getMessage());
            throw new DownloadFailedException(msg, ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOGGER.trace("Ignorable error", ex);
                }
            }
        }
    }

    /**
     * Retrieves a file from a given URL and returns the contents.
     *
     * @param url the URL of the file to download
     * @param useProxy whether to use the configured proxy when downloading
     * files
     * @return the content of the file
     * @throws DownloadFailedException is thrown if there is an error
     * downloading the file
     * @throws TooManyRequestsException thrown when a 429 is received
     * @throws ResourceNotFoundException thrown when a 404 is received
     */
    public String fetchContent(URL url, boolean useProxy) throws DownloadFailedException, TooManyRequestsException, ResourceNotFoundException {
        return fetchContent(url, useProxy, null, null);
    }

    /**
     * Retrieves a file from a given URL and returns the contents.
     *
     * @param url the URL of the file to download
     * @param useProxy whether to use the configured proxy when downloading
     * files
     * @return the content of the file
     * @param userKey the settings key for the username to be used
     * @param passwordKey the settings key for the password to be used
     * @throws DownloadFailedException is thrown if there is an error
     * downloading the file
     * @throws TooManyRequestsException thrown when a 429 is received
     * @throws ResourceNotFoundException thrown when a 404 is received
     */
    public String fetchContent(URL url, boolean useProxy, String userKey, String passwordKey)
            throws DownloadFailedException, TooManyRequestsException, ResourceNotFoundException {
        InputStream in = null;
        try (HttpResourceConnection conn = new HttpResourceConnection(settings, useProxy, userKey, passwordKey);
                ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            in = conn.fetch(url);
            IOUtils.copy(in, out);
            return out.toString(UTF8);
        } catch (IOException ex) {
            final String msg = format("Download failed, unable to retrieve '%s'; %s", url.toString(), ex.getMessage());
            throw new DownloadFailedException(msg, ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOGGER.trace("Ignorable error", ex);
                }
            }
        }
    }
}
