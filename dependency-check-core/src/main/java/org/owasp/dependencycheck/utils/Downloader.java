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
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/**
 * A utility to download files from the Internet.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class Downloader {
    
    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(Downloader.class.getName());
    /**
     * Private constructor for utility class.
     */
    private Downloader() {
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     *
     * @param url the URL of the file to download
     * @param outputPath the path to the save the file to
     * @throws DownloadFailedException is thrown if there is an error downloading the file
     */
    public static void fetchFile(URL url, File outputPath) throws DownloadFailedException {
        fetchFile(url, outputPath, true);
    }

    /**
     * Retrieves a file from a given URL and saves it to the outputPath.
     *
     * @param url the URL of the file to download
     * @param outputPath the path to the save the file to
     * @param useProxy whether to use the configured proxy when downloading files
     * @throws DownloadFailedException is thrown if there is an error downloading the file
     */
    public static void fetchFile(URL url, File outputPath, boolean useProxy) throws DownloadFailedException {
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            File file;
            try {
                file = new File(url.toURI());
            } catch (URISyntaxException ex) {
                final String msg = String.format("Download failed, unable to locate '%s'", url.toString());
                throw new DownloadFailedException(msg);
            }
            if (file.exists()) {
                try {
                    org.apache.commons.io.FileUtils.copyFile(file, outputPath);
                } catch (IOException ex) {
                    final String msg = String.format("Download failed, unable to copy '%s'", url.toString());
                    throw new DownloadFailedException(msg);
                }
            } else {
                final String msg = String.format("Download failed, file does not exist '%s'", url.toString());
                throw new DownloadFailedException(msg);
            }
        } else {
            HttpURLConnection conn = null;
            try {
                conn = URLConnectionFactory.createHttpURLConnection(url, useProxy);
                conn.setRequestProperty("Accept-Encoding", "gzip, deflate");
                conn.connect();
            } catch (IOException ex) {
                try {
                    if (conn != null) {
                        conn.disconnect();
                    }
                } finally {
                    conn = null;
                }
                throw new DownloadFailedException("Error downloading file.", ex);
            }
            final String encoding = conn.getContentEncoding();

            BufferedOutputStream writer = null;
            InputStream reader = null;
            try {
                if (encoding != null && "gzip".equalsIgnoreCase(encoding)) {
                    reader = new GZIPInputStream(conn.getInputStream());
                } else if (encoding != null && "deflate".equalsIgnoreCase(encoding)) {
                    reader = new InflaterInputStream(conn.getInputStream());
                } else {
                    reader = conn.getInputStream();
                }

                writer = new BufferedOutputStream(new FileOutputStream(outputPath));
                final byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = reader.read(buffer)) > 0) {
                    writer.write(buffer, 0, bytesRead);
                }
            } catch (Throwable ex) {
                throw new DownloadFailedException("Error saving downloaded file.", ex);
            } finally {
                if (writer != null) {
                    try {
                        writer.close();
                    } catch (Throwable ex) {
                        LOGGER.log(Level.FINEST,
                                "Error closing the writer in Downloader.", ex);
                    }
                }
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (Throwable ex) {
                        LOGGER.log(Level.FINEST,
                                "Error closing the reader in Downloader.", ex);
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
     * Makes an HTTP Head request to retrieve the last modified date of the given URL. If the file:// protocol is
     * specified, then the lastTimestamp of the file is returned.
     *
     * @param url the URL to retrieve the timestamp from
     * @return an epoch timestamp
     * @throws DownloadFailedException is thrown if an exception occurs making the HTTP request
     */
    public static long getLastModified(URL url) throws DownloadFailedException {
        long timestamp = 0;
        //TODO add the FTP protocol?
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            File lastModifiedFile;
            try {
                lastModifiedFile = new File(url.toURI());
            } catch (URISyntaxException ex) {
                final String msg = String.format("Unable to locate '%s'; is the cve.url-2.0.modified property set correctly?", url.toString());
                throw new DownloadFailedException(msg);
            }
            timestamp = lastModifiedFile.lastModified();
        } else {
            HttpURLConnection conn = null;
            try {
                conn = URLConnectionFactory.createHttpURLConnection(url);
                conn.setRequestMethod("HEAD");
                conn.connect();
                timestamp = conn.getLastModified();
            } catch (URLConnectionFailureException ex) {
                throw new DownloadFailedException("Error creating URL Connection for HTTP HEAD request.", ex);
            } catch (IOException ex) {
                throw new DownloadFailedException("Error making HTTP HEAD request.", ex);
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
}
