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
import java.io.IOException;
import java.net.URL;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.lang3.StringUtils;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
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
    private File file;

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

        try {
            this.file = File.createTempFile("cve" + nvdCveInfo.getId() + '_', ".json.gz", settings.getTempDirectory());
        } catch (IOException ex) {
            throw new UpdateException("Unable to create temporary files", ex);
        }
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
     * Get the value of file.
     *
     * @return the value of file
     */
    public File getFile() {
        return file;
    }

    @Override
    public Future<ProcessTask> call() throws Exception {
        final long waitTime = settings.getInt(Settings.KEYS.CVE_DOWNLOAD_WAIT_TIME, 4000);
        long startDownload = 0;
        final NvdCache cache = new NvdCache(settings);
        try {
            final URL url1 = new URL(nvdCveInfo.getUrl());
            if (cache.notInCache(url1, file)) {
                Thread.sleep(waitTime);
                LOGGER.info("Download Started for NVD CVE - {}", nvdCveInfo.getId());
                startDownload = System.currentTimeMillis();
                final int downloadAttempts = 5;
                for (int x = 2; x <= downloadAttempts && !attemptDownload(url1, x == downloadAttempts); x++) {
                    LOGGER.info("Download Attempt {} for NVD CVE - {}", x, nvdCveInfo.getId());
                    Thread.sleep(waitTime * (x / 2));
                }
                if (file.isFile() && file.length() > 0) {
                    LOGGER.info("Download Complete for NVD CVE - {}  ({} ms)", nvdCveInfo.getId(),
                            System.currentTimeMillis() - startDownload);
                    cache.storeInCache(url1, file);
                } else {
                    throw new DownloadFailedException("Unable to download NVD CVE " + nvdCveInfo.getId());
                }
            }
            if (this.processorService == null) {
                return null;
            }
            final ProcessTask task = new ProcessTask(cveDB, this, settings);
            final Future<ProcessTask> val = this.processorService.submit(task);
            return val;

        } catch (Throwable ex) {
            LOGGER.error("Error downloading NVD CVE - {} Reason: {}", nvdCveInfo.getId(), ex.getMessage());
            throw ex;
        } finally {
            settings.cleanup(false);
        }
    }

    private boolean attemptDownload(final URL url1, boolean showLog) throws TooManyRequestsException, ResourceNotFoundException {
        try {
            final Downloader downloader = new Downloader(settings);
            downloader.fetchFile(url1, file, Settings.KEYS.CVE_USER, Settings.KEYS.CVE_PASSWORD);
        } catch (DownloadFailedException ex) {
            if (showLog) {
                LOGGER.error("Download Failed for NVD CVE - {}\nSome CVEs may not be reported. Reason: {}",
                        nvdCveInfo.getId(), ex.getMessage());
                if (settings.getString(Settings.KEYS.PROXY_SERVER) == null) {
                    LOGGER.error("If you are behind a proxy you may need to configure dependency-check to use the proxy.");
                }
                LOGGER.debug("", ex);
            }
            return false;
        }
        return true;
    }

    /**
     * Attempts to delete the files that were downloaded.
     */
    public void cleanup() {
        if (file != null && file.exists() && !file.delete()) {
            LOGGER.debug("Failed to delete first temporary file {}", file.toString());
            file.deleteOnExit();
        }
    }

    /**
     * Returns true if the process task is for the modified json file from the
     * NVD.
     *
     * @return <code>true</code> if the process task is for the modified data;
     * otherwise <code>false</code>
     */
    public boolean isModified() {
        return StringUtils.containsIgnoreCase(file.toString(), "modified");
    }
}
