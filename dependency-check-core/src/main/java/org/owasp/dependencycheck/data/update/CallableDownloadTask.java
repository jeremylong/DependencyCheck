/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.owasp.dependencycheck.data.update;

import java.io.File;
import java.net.URL;
import java.util.concurrent.Callable;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;

/**
 * A callable object to download two files.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class CallableDownloadTask implements Callable<CallableDownloadTask> {

    /**
     * Simple constructor for the callable download task.
     *
     * @param nvdCveInfo the nvd cve info
     * @param first the first file
     * @param second the second file
     */
    public CallableDownloadTask(NvdCveInfo nvdCveInfo, File first, File second) {
        this.nvdCveInfo = nvdCveInfo;
        this.first = first;
        this.second = second;
    }
    private NvdCveInfo nvdCveInfo;

    /**
     * Get the value of nvdCveInfo
     *
     * @return the value of nvdCveInfo
     */
    public NvdCveInfo getNvdCveInfo() {
        return nvdCveInfo;
    }

    /**
     * Set the value of nvdCveInfo
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
     * the first url.
     */
    private URL firstUrl;

    /**
     * Get the value of firstUrl.
     *
     * @return the value of firstUrl
     */
    public URL getFirstUrl() {
        return firstUrl;
    }

    /**
     * Set the value of firstUrl.
     *
     * @param firstUrl new value of firstUrl
     */
    public void setFirstUrl(URL firstUrl) {
        this.firstUrl = firstUrl;
    }
    /**
     * the second url.
     */
    private URL secondUrl;

    /**
     * Get the value of secondURL.
     *
     * @return the value of secondURL
     */
    public URL getSecondUrl() {
        return secondUrl;
    }

    /**
     * Set the value of secondUrl.
     *
     * @param secondURL new value of secondUrl
     */
    public void setSecondUrl(URL secondUrl) {
        this.secondUrl = secondUrl;
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
    public CallableDownloadTask call() throws Exception {
        try {
            final URL url_1 = new URL(nvdCveInfo.getUrl());
            final URL url_2 = new URL(nvdCveInfo.getOldSchemaVersionUrl());
            String msg = String.format("Download Started for NVD CVE - %s", nvdCveInfo.getId());
            Logger.getLogger(CallableDownloadTask.class.getName()).log(Level.INFO, msg);
            Downloader.fetchFile(url_1, first);
            Downloader.fetchFile(url_2, second);
            msg = String.format("Download Complete for NVD CVE - %s", nvdCveInfo.getId());
            Logger.getLogger(CallableDownloadTask.class.getName()).log(Level.INFO, msg);
        } catch (DownloadFailedException ex) {
            this.exception = ex;
        }
        return this;
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
