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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import static java.lang.String.format;

import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/**
 * A utility to download files from the Internet.
 *
 * @author Jeremy Long
 * @version $Id: $Id
 */
public class HttpResourceConnection implements AutoCloseable {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpResourceConnection.class);
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
     * The URL conn factory.
     */
    private final URLConnectionFactory connFactory;
    /**
     * The current conn.
     */
    private HttpURLConnection connection = null;
    /**
     * Whether or not the conn will use the defined proxy.
     */
    private boolean usesProxy;

    /**
     * The settings key for the username to be used.
     */
    private String userKey = null;
    /**
     * The settings key for the password to be used.
     */
    private String passwordKey = null;

    /**
     * Constructs a new HttpResourceConnection object.
     *
     * @param settings the configured settings
     */
    public HttpResourceConnection(Settings settings) {
        this(settings, true);
    }

    /**
     * Constructs a new HttpResourceConnection object.
     *
     * @param settings the configured settings
     * @param usesProxy control whether this conn will use the defined proxy.
     */
    public HttpResourceConnection(Settings settings, boolean usesProxy) {
        this.settings = settings;
        this.connFactory = new URLConnectionFactory(settings);
        this.usesProxy = usesProxy;
    }

    /**
     * Constructs a new HttpResourceConnection object.
     *
     * @param settings the configured settings
     * @param usesProxy control whether this conn will use the defined proxy
     * @param userKey the settings key for the username to be used
     * @param passwordKey the settings key for the password to be used
     */
    public HttpResourceConnection(Settings settings, boolean usesProxy, String userKey, String passwordKey) {
        this.settings = settings;
        this.connFactory = new URLConnectionFactory(settings);
        this.usesProxy = usesProxy;
        this.userKey = userKey;
        this.passwordKey = passwordKey;
    }

    /**
     * Retrieves the resource identified by the given URL and returns the
     * InputStream.
     *
     * @param url the URL of the resource to download
     * @return the stream to read the retrieved content from
     * @throws org.owasp.dependencycheck.utils.DownloadFailedException is thrown
     * if there is an error downloading the resource
     * @throws TooManyRequestsException thrown when a 429 is received
     * @throws ResourceNotFoundException thrown when a 404 is received
     */
    public InputStream fetch(URL url) throws DownloadFailedException, TooManyRequestsException, ResourceNotFoundException {
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            final File file;
            try {
                file = new File(url.toURI());
            } catch (URISyntaxException ex) {
                final String msg = format("Download failed, unable to locate '%s'", url.toString());
                throw new DownloadFailedException(msg);
            }
            if (file.exists()) {
                try {
                    return new FileInputStream(file);
                } catch (IOException ex) {
                    final String msg = format("Download failed, unable to rerieve '%s'", url.toString());
                    throw new DownloadFailedException(msg, ex);
                }
            } else {
                final String msg = format("Download failed, file ('%s') does not exist", url.toString());
                throw new DownloadFailedException(msg);
            }
        } else {
            if (connection != null) {
                LOGGER.warn("HTTP URL Connection was not properly closed");
                connection.disconnect();
                connection = null;
            }
            connection = obtainConnection(url);

            final String encoding = connection.getContentEncoding();
            try {
                if (encoding != null && "gzip".equalsIgnoreCase(encoding)) {
                    return new GZIPInputStream(connection.getInputStream());
                } else if (encoding != null && "deflate".equalsIgnoreCase(encoding)) {
                    return new InflaterInputStream(connection.getInputStream());
                } else {
                    return connection.getInputStream();
                }
            } catch (IOException ex) {
                checkForCommonExceptionTypes(ex);
                final String msg = format("Error retrieving '%s'%nConnection Timeout: %d%nEncoding: %s%n",
                        url.toString(), connection.getConnectTimeout(), encoding);
                throw new DownloadFailedException(msg, ex);
            } catch (Exception ex) {
                final String msg = format("Unexpected exception retrieving '%s'%nConnection Timeout: %d%nEncoding: %s%n",
                        url.toString(), connection.getConnectTimeout(), encoding);
                throw new DownloadFailedException(msg, ex);
            }
        }
    }

    /**
     * Obtains the HTTP URL Connection.
     *
     * @param url the URL
     * @return the HTTP URL Connection
     * @throws DownloadFailedException thrown if there is an error creating the
     * HTTP URL Connection
     * @throws TooManyRequestsException thrown when a 429 is received
     * @throws ResourceNotFoundException thrown when a 404 is received
     */
    private HttpURLConnection obtainConnection(URL url) throws DownloadFailedException, TooManyRequestsException, ResourceNotFoundException {
        HttpURLConnection conn = null;
        try {
            LOGGER.debug("Attempting retrieval of {}", url.toString());
            conn = connFactory.createHttpURLConnection(url, this.usesProxy);
            if (userKey != null && passwordKey != null) {
                connFactory.addBasicAuthentication(conn, userKey, passwordKey);
            }
            conn.setRequestProperty("Accept-Encoding", "gzip, deflate");
            conn.connect();
            int status = conn.getResponseCode();
            final String message = conn.getResponseMessage();
            int redirectCount = 0;
            // TODO - should this get replaced by using the conn.setInstanceFollowRedirects(true);
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
                conn = connFactory.createHttpURLConnection(new URL(location), this.usesProxy);
                conn.setRequestProperty("Accept-Encoding", "gzip, deflate");
                conn.connect();
                status = conn.getResponseCode();
            }
            if (status == 404) {
                try {
                    conn.disconnect();
                } finally {
                    conn = null;
                }
                throw new ResourceNotFoundException("Requested resource does not exists - received a 404");
            } else if (status == 429) {
                try {
                    conn.disconnect();
                } finally {
                    conn = null;
                }
                throw new TooManyRequestsException("Download failed - too many connection requests");
            } else if (status != 200) {
                try {
                    conn.disconnect();
                } finally {
                    conn = null;
                }
                final String msg = format("Error retrieving %s; received response code %s; %s", url.toString(), status, message);
                LOGGER.error(msg);
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
        return conn;
    }

    /**
     * Makes an HTTP Head request to retrieve the last modified date of the
     * given URL. If the file:// protocol is specified, then the lastTimestamp
     * of the file is returned.
     *
     * @param url the URL to retrieve the timestamp from
     * @return an epoch timestamp
     * @throws org.owasp.dependencycheck.utils.DownloadFailedException is thrown
     * if an exception occurs making the HTTP request
     * @deprecated this method is no longer used to check the last modified date
     * of the NVD. This method will be removed in a future release.
     */
    @Deprecated
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
     * @deprecated this method is no longer used to check the last modified date
     * of the NVD. This method will be removed in a future release.
     */
    @Deprecated
    private long getLastModified(URL url, boolean isRetry) throws DownloadFailedException {
        final long timestamp;
        //TODO use the obtain connection instead of this mostly duplicated code
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            final File lastModifiedFile;
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
                LOGGER.error(format("IO Exception connecting to %s: %s", url, ex.getMessage()));
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
     * {@inheritDoc}
     * <p>
     * Releases the underlying HTTP URL Connection.
     */
    @Override
    public void close() {
        if (connection != null) {
            try {
                connection.disconnect();
            } finally {
                connection = null;
            }
        }
    }

    /**
     * Returns whether or not the connection has been closed.
     *
     * @return whether or not the connection has been closed
     */
    public boolean isClosed() {
        return connection == null;
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
        return settings.getBoolean(Settings.KEYS.DOWNLOADER_QUICK_QUERY_TIMESTAMP, true);
    }

    /**
     * Analyzes the IOException, logs the appropriate information for debugging
     * purposes, and then throws a DownloadFailedException that wraps the IO
     * Exception for common IO Exceptions. This is to provide additional details
     * to assist in resolution of the exception.
     *
     * @param ex the original exception
     * @throws org.owasp.dependencycheck.utils.DownloadFailedException a wrapper
     * exception that contains the original exception as the cause
     */
    public void checkForCommonExceptionTypes(IOException ex) throws DownloadFailedException {
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
}
