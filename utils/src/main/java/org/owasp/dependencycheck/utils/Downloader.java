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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.BufferedOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;
import static java.lang.String.format;

/**
 * A utility to download files from the Internet.
 *
 * @author Jeremy Long
 */
public final class Downloader {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(Downloader.class);
    /**
     * The maximum number of redirects that will be followed when attempting to
     * download a file.
     */
    private static final int MAX_REDIRECT_ATTEMPTS = 5;

    /**
     * The default HTTP request method for query timestamp
     */
    private static final String HEAD = "HEAD";

    /**
     * The HTTP request method which can be used by query timestamp
     */
    private static final String GET = "GET";

    /**
     * The configured settings.
     */
    private final Settings settings;

    /**
     * The URL connection facctory.
     */
    private final URLConnectionFactory connFactory;

    /**
     * Constructs a new downloader object.
     *
     * @param settings the configured settings
     */
    public Downloader(Settings settings) {
        this.settings = settings;
        this.connFactory = new URLConnectionFactory(settings);
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     *
     * @param url the URL of the file to download
     * @param outputPath the path to the save the file to
     * @throws DownloadFailedException is thrown if there is an error
     * downloading the file
     */
    public void fetchFile(URL url, File outputPath) throws DownloadFailedException {
        fetchFile(url, outputPath, true);
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     *
     * @param url the URL of the file to download
     * @param outputPath the path to the save the file to
     * @param useProxy whether to use the configured proxy when downloading
     * files
     * @throws DownloadFailedException is thrown if there is an error
     * downloading the file
     */
    public void fetchFile(URL url, File outputPath, boolean useProxy) throws DownloadFailedException {
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            File file;
            try {
                file = new File(url.toURI());
            } catch (URISyntaxException ex) {
                final String msg = format("Download failed, unable to locate '%s'", url.toString());
                throw new DownloadFailedException(msg);
            }
            if (file.exists()) {
                try {
                    org.apache.commons.io.FileUtils.copyFile(file, outputPath);
                } catch (IOException ex) {
                    final String msg = format("Download failed, unable to copy '%s' to '%s'", url.toString(), outputPath.getAbsolutePath());
                    throw new DownloadFailedException(msg, ex);
                }
            } else {
                final String msg = format("Download failed, file ('%s') does not exist", url.toString());
                throw new DownloadFailedException(msg);
            }
        } else {
            HttpURLConnection conn = null;
            try {
                LOGGER.debug("Attempting download of {}", url.toString());
                conn = connFactory.createHttpURLConnection(url, useProxy);
                conn.setRequestProperty("Accept-Encoding", "gzip, deflate");
                conn.connect();
                int status = conn.getResponseCode();
                int redirectCount = 0;
                while ((status == HttpURLConnection.HTTP_MOVED_TEMP
                        || status == HttpURLConnection.HTTP_MOVED_PERM
                        || status == HttpURLConnection.HTTP_SEE_OTHER)
                        && MAX_REDIRECT_ATTEMPTS > redirectCount++) {
                    final String location = conn.getHeaderField("Location");
                    try {
                        conn.disconnect();
                    } finally {
                        conn = null;
                    }
                    LOGGER.debug("Download is being redirected from {} to {}", url.toString(), location);
                    conn = connFactory.createHttpURLConnection(new URL(location), useProxy);
                    conn.setRequestProperty("Accept-Encoding", "gzip, deflate");
                    conn.connect();
                    status = conn.getResponseCode();
                }
                if (status != 200) {
                    try {
                        conn.disconnect();
                    } finally {
                        conn = null;
                    }
                    final String msg = format("Error downloading file %s; received response code %s.", url.toString(), status);
                    throw new DownloadFailedException(msg);

                }
            } catch (IOException ex) {
                try {
                    if (conn != null) {
                        conn.disconnect();
                    }
                } finally {
                    conn = null;
                }
                if ("Connection reset".equalsIgnoreCase(ex.getMessage())) {
                    final String msg = format("TLS Connection Reset%nPlease see "
                            + "http://jeremylong.github.io/DependencyCheck/data/tlsfailure.html "
                            + "for more information regarding how to resolve the issue.");
                    LOGGER.error(msg);
                    throw new DownloadFailedException(msg, ex);
                }
                final String msg = format("Error downloading file %s; unable to connect.", url.toString());
                throw new DownloadFailedException(msg, ex);
            }

            final String encoding = conn.getContentEncoding();
            InputStream reader = null;
            try (OutputStream out = new FileOutputStream(outputPath);
                    BufferedOutputStream writer = new BufferedOutputStream(out)) {
                if (encoding != null && "gzip".equalsIgnoreCase(encoding)) {
                    reader = new GZIPInputStream(conn.getInputStream());
                } else if (encoding != null && "deflate".equalsIgnoreCase(encoding)) {
                    reader = new InflaterInputStream(conn.getInputStream());
                } else {
                    reader = conn.getInputStream();
                }

                final byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = reader.read(buffer)) > 0) {
                    writer.write(buffer, 0, bytesRead);
                }
                LOGGER.debug("Download of {} complete", url.toString());
            } catch (IOException ex) {
                checkForCommonExceptionTypes(ex);
                final String msg = format("Error saving '%s' to file '%s'%nConnection Timeout: %d%nEncoding: %s%n",
                        url.toString(), outputPath.getAbsolutePath(), conn.getConnectTimeout(), encoding);
                throw new DownloadFailedException(msg, ex);
            } catch (Exception ex) {
                final String msg = format("Unexpected exception saving '%s' to file '%s'%nConnection Timeout: %d%nEncoding: %s%n",
                        url.toString(), outputPath.getAbsolutePath(), conn.getConnectTimeout(), encoding);
                throw new DownloadFailedException(msg, ex);
            } finally {
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (IOException ex) {
                        LOGGER.trace("Error closing the reader in Downloader.", ex);
                    }
                }
                try {
                    conn.disconnect();
                } finally {
                    conn = null;
                }
            }
        }
    }

    /**
     * Makes an HTTP Head request to retrieve the last modified date of the
     * given URL. If the file:// protocol is specified, then the lastTimestamp
     * of the file is returned.
     *
     * @param url the URL to retrieve the timestamp from
     * @return an epoch timestamp
     * @throws DownloadFailedException is thrown if an exception occurs making
     * the HTTP request
     */
    public long getLastModified(URL url) throws DownloadFailedException {
        return getLastModified(url, false);
    }

    /**
     * Makes an HTTP Head request to retrieve the last modified date of the
     * given URL. If the file:// protocol is specified, then the lastTimestamp
     * of the file is returned.
     *
     * @param url the URL to retrieve the timestamp from
     * @param isRetry indicates if this is a retry - to prevent endless loop and
     * stack overflow
     * @return an epoch timestamp
     * @throws DownloadFailedException is thrown if an exception occurs making
     * the HTTP request
     */
    private long getLastModified(URL url, boolean isRetry) throws DownloadFailedException {
        long timestamp = 0;
        //TODO add the FTP protocol?
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            File lastModifiedFile;
            try {
                lastModifiedFile = new File(url.toURI());
            } catch (URISyntaxException ex) {
                final String msg = format("Unable to locate '%s'", url.toString());
                throw new DownloadFailedException(msg, ex);
            }
            timestamp = lastModifiedFile.lastModified();
        } else {
            final String httpMethod = determineHttpMethod();
            HttpURLConnection conn = null;
            try {
                conn = connFactory.createHttpURLConnection(url);
                conn.setRequestMethod(httpMethod);
                conn.connect();
                final int t = conn.getResponseCode();
                if (t >= 200 && t < 300) {
                    timestamp = conn.getLastModified();
                } else {
                    throw new DownloadFailedException(format("%s request returned a non-200 status code: %s", httpMethod, url));
                }
            } catch (URLConnectionFailureException ex) {
                throw new DownloadFailedException(format("Error creating URL Connection for HTTP %s request: %s", httpMethod, url), ex);
            } catch (IOException ex) {
                checkForCommonExceptionTypes(ex);
                LOGGER.error(String.format("IO Exception connecting to %s: %s", url, ex.getMessage()));
                LOGGER.debug("Exception details", ex);
                if (ex.getCause() != null) {
                    LOGGER.debug("IO Exception cause: " + ex.getCause().getMessage(), ex.getCause());
                }
                try {
                    //retry
                    if (!isRetry && settings.getBoolean(Settings.KEYS.DOWNLOADER_QUICK_QUERY_TIMESTAMP)) {
                        settings.setBoolean(Settings.KEYS.DOWNLOADER_QUICK_QUERY_TIMESTAMP, false);
                        return getLastModified(url, true);
                    }
                } catch (InvalidSettingException ex1) {
                    LOGGER.debug("invalid setting?", ex1);
                }
                throw new DownloadFailedException(format("Error making HTTP %s request to %s", httpMethod, url), ex);
            } finally {
                if (conn != null) {
                    try {
                        conn.disconnect();
                    } finally {
                        conn = null;
                    }
                }
            }
        }
        return timestamp;
    }

    /**
     * Analyzes the IOException, logs the appropriate information for debugging
     * purposes, and then throws a DownloadFailedException that wraps the IO
     * Exception for common IO Exceptions. This is to provide additional details
     * to assist in resolution of the exception.
     *
     * @param ex the original exception
     * @throws DownloadFailedException a wrapper exception that contains the
     * original exception as the cause
     */
    protected synchronized void checkForCommonExceptionTypes(IOException ex) throws DownloadFailedException {
        Throwable cause = ex;
        while (cause != null) {
            if (cause instanceof java.net.UnknownHostException) {
                final String msg = format("Unable to resolve domain '%s'", cause.getMessage());
                LOGGER.error(msg);
                throw new DownloadFailedException(msg);
            }
            if (cause instanceof InvalidAlgorithmParameterException) {
                final String keystore = System.getProperty("javax.net.ssl.keyStore");
                final String version = System.getProperty("java.version");
                final String vendor = System.getProperty("java.vendor");
                LOGGER.info("Error making HTTPS request - InvalidAlgorithmParameterException");
                LOGGER.info("There appears to be an issue with the installation of Java and the cacerts."
                        + "See closed issue #177 here: https://github.com/jeremylong/DependencyCheck/issues/177");
                LOGGER.info("Java Info:\njavax.net.ssl.keyStore='{}'\njava.version='{}'\njava.vendor='{}'",
                        keystore, version, vendor);
                throw new DownloadFailedException("Error making HTTPS request. Please see the log for more details.");
            }
            cause = cause.getCause();
        }
    }

    /**
     * Returns the HEAD or GET HTTP method. HEAD is the default.
     *
     * @return the HTTP method to use
     */
    private String determineHttpMethod() {
        return isQuickQuery() ? HEAD : GET;
    }

    /**
     * Determines if the HTTP method GET or HEAD should be used to check the
     * timestamp on external resources.
     *
     * @return true if configured to use HEAD requests
     */
    private boolean isQuickQuery() {
        boolean quickQuery;

        try {
            quickQuery = settings.getBoolean(Settings.KEYS.DOWNLOADER_QUICK_QUERY_TIMESTAMP, true);
        } catch (InvalidSettingException e) {
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("Invalid settings : {}", e.getMessage(), e);
            }
            quickQuery = true;
        }
        return quickQuery;
    }
}
