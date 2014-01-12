/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.task;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.update.NvdCveInfo;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;

/**
 * A callable object to download two files.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class CallableDownloadTask implements Callable<Future<ProcessTask>> {

    /**
     * Simple constructor for the callable download task.
     *
     * @param nvdCveInfo the NVD CVE info
     * @param processor the processor service to submit the downloaded files to
     * @param cveDB the CVE DB to use to store the vulnerability data
     */
    public CallableDownloadTask(NvdCveInfo nvdCveInfo, ExecutorService processor, CveDB cveDB) {
        this.nvdCveInfo = nvdCveInfo;
        this.processorService = processor;
        this.cveDB = cveDB;

        final File file1;
        final File file2;


        try {
            file1 = File.createTempFile("cve" + nvdCveInfo.getId() + "_", ".xml");
            file2 = File.createTempFile("cve_1_2_" + nvdCveInfo.getId() + "_", ".xml");
        } catch (IOException ex) {
            return;
        }
        this.first = file1;
        this.second = file2;

    }
    /**
     * The CVE DB to use when processing the files.
     */
    private CveDB cveDB;
    /**
     * The processor service to pass the results of the download to.
     */
    private ExecutorService processorService;
    /**
     * The NVD CVE Meta Data.
     */
    private NvdCveInfo nvdCveInfo;

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
     * a file.
     */
    private File first;

    /**
     * Get the value of first.
     *
     * @return the value of first
     */
    public File getFirst() {
        return first;
    }

    /**
     * Set the value of first.
     *
     * @param first new value of first
     */
    public void setFirst(File first) {
        this.first = first;
    }
    /**
     * a file.
     */
    private File second;

    /**
     * Get the value of second.
     *
     * @return the value of second
     */
    public File getSecond() {
        return second;
    }

    /**
     * Set the value of second.
     *
     * @param second new value of second
     */
    public void setSecond(File second) {
        this.second = second;
    }
    /**
     * A placeholder for an exception.
     */
    private Exception exception = null;

    /**
     * Get the value of exception.
     *
     * @return the value of exception
     */
    public Exception getException() {
        return exception;
    }

    /**
     * returns whether or not an exception occurred during download.
     *
     * @return whether or not an exception occurred during download
     */
    public boolean hasException() {
        return exception != null;
    }

    @Override
    public Future<ProcessTask> call() throws Exception {
        try {
            final URL url1 = new URL(nvdCveInfo.getUrl());
            final URL url2 = new URL(nvdCveInfo.getOldSchemaVersionUrl());
            String msg = String.format("Download Started for NVD CVE - %s", nvdCveInfo.getId());
            Logger.getLogger(CallableDownloadTask.class.getName()).log(Level.INFO, msg);
            try {
                Downloader.fetchFile(url1, first);
                Downloader.fetchFile(url2, second);
            } catch (DownloadFailedException ex) {
                msg = String.format("Download Failed for NVD CVE - %s%nSome CVEs may not be reported.", nvdCveInfo.getId());
                Logger.getLogger(CallableDownloadTask.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(CallableDownloadTask.class.getName()).log(Level.FINE, null, ex);
                return null;
            }

            msg = String.format("Download Complete for NVD CVE - %s", nvdCveInfo.getId());
            Logger.getLogger(CallableDownloadTask.class.getName()).log(Level.INFO, msg);

            final ProcessTask task = new ProcessTask(cveDB, this);
            return this.processorService.submit(task);

        } catch (Throwable ex) {
            final String msg = String.format("An exception occurred downloading NVD CVE - %s%nSome CVEs may not be reported.", nvdCveInfo.getId());
            Logger.getLogger(CallableDownloadTask.class.getName()).log(Level.WARNING, msg);
            Logger.getLogger(CallableDownloadTask.class.getName()).log(Level.FINE, "Download Task Failed", ex);
        }
        return null;
    }

    /**
     * Attempts to delete the files that were downloaded.
     */
    public void cleanup() {
        boolean deleted = false;
        try {
            if (first != null && first.exists()) {
                deleted = first.delete();
            }
        } finally {
            if (first != null && (first.exists() || !deleted)) {
                first.deleteOnExit();
            }
        }
        try {
            deleted = false;
            if (second != null && second.exists()) {
                deleted = second.delete();
            }
        } finally {
            if (second != null && (second.exists() || !deleted)) {
                second.deleteOnExit();
            }
        }
    }
}
