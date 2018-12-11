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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.nvd;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.ExtractionUtil;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A callable object to download two files.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class DownloadTask implements Callable<Future<ProcessTask>> {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DownloadTask.class);
    /**
     * The CVE DB to use when processing the files.
     */
    private final CveDB cveDB;
    /**
     * The processor service to pass the results of the download to.
     */
    private final ExecutorService processorService;
    /**
     * The NVD CVE Meta Data.
     */
    private NvdCveInfo nvdCveInfo;
    /**
     * A reference to the global settings object.
     */
    private final Settings settings;
    /**
     * a file.
     */
    private File first;
    /**
     * a file.
     */
    private File second;

    /**
     * Simple constructor for the callable download task.
     *
     * @param nvdCveInfo the NVD CVE info
     * @param processor the processor service to submit the downloaded files to
     * @param cveDB the CVE DB to use to store the vulnerability data
     * @param settings a reference to the global settings object; this is
     * necessary so that when the thread is started the dependencies have a
     * correct reference to the global settings.
     * @throws UpdateException thrown if temporary files could not be created
     */
    public DownloadTask(NvdCveInfo nvdCveInfo, ExecutorService processor, CveDB cveDB, Settings settings) throws UpdateException {
        this.nvdCveInfo = nvdCveInfo;
        this.processorService = processor;
        this.cveDB = cveDB;
        this.settings = settings;

        final File file1;
        final File file2;

        try {
            file1 = File.createTempFile("cve" + nvdCveInfo.getId() + '_', ".xml", settings.getTempDirectory());
            file2 = File.createTempFile("cve_1_2_" + nvdCveInfo.getId() + '_', ".xml", settings.getTempDirectory());
        } catch (IOException ex) {
            throw new UpdateException("Unable to create temporary files", ex);
        }
        this.first = file1;
        this.second = file2;

    }

    /**
     * Get the value of nvdCveInfo.
     *
     * @return the value of nvdCveInfo
     */
    public NvdCveInfo getNvdCveInfo() {
        return nvdCveInfo;
    }

    /**
     * Set the value of nvdCveInfo.
     *
     * @param nvdCveInfo new value of nvdCveInfo
     */
    public void setNvdCveInfo(NvdCveInfo nvdCveInfo) {
        this.nvdCveInfo = nvdCveInfo;
    }

    /**
     * Get the value of first.
     *
     * @return the value of first
     */
    public File getFirst() {
        return first;
    }

    /**
     * Get the value of second.
     *
     * @return the value of second
     */
    public File getSecond() {
        return second;
    }

    @Override
    public Future<ProcessTask> call() throws Exception {
        try {
            final URL url1 = new URL(nvdCveInfo.getUrl());
            final URL url2 = new URL(nvdCveInfo.getOldSchemaVersionUrl());
            LOGGER.info("Download Started for NVD CVE - {}", nvdCveInfo.getId());
            final long startDownload = System.currentTimeMillis();
            try {
                final Downloader downloader = new Downloader(settings);
                downloader.fetchFile(url1, first);
                downloader.fetchFile(url2, second);
            } catch (DownloadFailedException ex) {
                LOGGER.warn("Download Failed for NVD CVE - {}\nSome CVEs may not be reported.", nvdCveInfo.getId());
                if (settings.getString(Settings.KEYS.PROXY_SERVER) == null) {
                    LOGGER.info("If you are behind a proxy you may need to configure dependency-check to use the proxy.");
                }
                LOGGER.debug("", ex);
                return null;
            }
            if (url1.toExternalForm().endsWith(".xml.gz") && !isXml(first)) {
                ExtractionUtil.extractGzip(first);
            }
            if (url2.toExternalForm().endsWith(".xml.gz") && !isXml(second)) {
                ExtractionUtil.extractGzip(second);
            }

            if (url1.toExternalForm().endsWith(".xml.zip") && !isXml(first)) {
                ExtractionUtil.extractZip(first);
            }
            if (url2.toExternalForm().endsWith(".xml.zip") && !isXml(second)) {
                ExtractionUtil.extractZip(second);
            }

            LOGGER.info("Download Complete for NVD CVE - {}  ({} ms)", nvdCveInfo.getId(),
                    System.currentTimeMillis() - startDownload);
            if (this.processorService == null) {
                return null;
            }
            final ProcessTask task = new ProcessTask(cveDB, this, settings);
            return this.processorService.submit(task);

        } catch (Throwable ex) {
            LOGGER.warn("An exception occurred downloading NVD CVE - {}\nSome CVEs may not be reported.", nvdCveInfo.getId());
            LOGGER.debug("Download Task Failed", ex);
        } finally {
            settings.cleanup(false);
        }
        return null;
    }

    /**
     * Attempts to delete the files that were downloaded.
     */
    public void cleanup() {
        if (first != null && first.exists() && !first.delete()) {
            LOGGER.debug("Failed to delete first temporary file {}", first.toString());
            first.deleteOnExit();
        }
        if (second != null && second.exists() && !second.delete()) {
            LOGGER.debug("Failed to delete second temporary file {}", second.toString());
            second.deleteOnExit();
        }
    }

    /**
     * Checks the file header to see if it is an XML file.
     *
     * @param file the file to check
     * @return true if the file is XML
     */
    public static boolean isXml(File file) {
        if (file == null || !file.isFile()) {
            return false;
        }
        try (InputStream is = new FileInputStream(file)) {
            final byte[] buf = new byte[5];
            final int read;
            read = is.read(buf);
            return read == 5
                    && buf[0] == '<'
                    && (buf[1] == '?')
                    && (buf[2] == 'x' || buf[2] == 'X')
                    && (buf[3] == 'm' || buf[3] == 'M')
                    && (buf[4] == 'l' || buf[4] == 'L');
        } catch (IOException ex) {
            LOGGER.debug("Error checking if file is xml", ex);
            return false;
        }
    }
}
