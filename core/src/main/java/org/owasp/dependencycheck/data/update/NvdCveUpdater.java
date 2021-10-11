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
package org.owasp.dependencycheck.data.update;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.util.Calendar;
import java.util.HashSet;
import java.util.Set;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import javax.annotation.concurrent.ThreadSafe;
import org.apache.commons.io.FileUtils;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvd.json.MetaProperties;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;

import static org.owasp.dependencycheck.data.nvdcve.DatabaseProperties.MODIFIED;

import org.owasp.dependencycheck.data.update.exception.InvalidDataException;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.data.update.nvd.DownloadTask;
import org.owasp.dependencycheck.data.update.nvd.NvdCache;
import org.owasp.dependencycheck.data.update.nvd.NvdCveInfo;
import org.owasp.dependencycheck.data.update.nvd.ProcessTask;
import org.owasp.dependencycheck.utils.DateUtil;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.owasp.dependencycheck.utils.Downloader;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.ResourceNotFoundException;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.TooManyRequestsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class responsible for updating the NVD CVE data.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class NvdCveUpdater implements CachedWebDataSource {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NvdCveUpdater.class);
    /**
     * The thread pool size to use for CPU-intense tasks.
     */
    private static final int PROCESSING_THREAD_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    /**
     * The thread pool size to use when downloading files.
     */
    private static final int DOWNLOAD_THREAD_POOL_SIZE = Math.round(1.5f * Runtime.getRuntime().availableProcessors());
    /**
     * ExecutorService for CPU-intense processing tasks.
     */
    private ExecutorService processingExecutorService = null;
    /**
     * ExecutorService for tasks that involve blocking activities and are not
     * very CPU-intense, e.g. downloading files.
     */
    private ExecutorService downloadExecutorService = null;
    /**
     * The configured settings.
     */
    private Settings settings;
    /**
     * Reference to the DAO.
     */
    private CveDB cveDb = null;
    /**
     * The properties obtained from the database.
     */
    private DatabaseProperties dbProperties = null;

    /**
     * Downloads the latest NVD CVE XML file from the web and imports it into
     * the current CVE Database. A lock on a file is obtained in an attempt to
     * prevent more then one thread/JVM from updating the database at the same
     * time. This method may sleep upto 5 minutes.
     *
     * @param engine a reference to the dependency-check engine
     * @return whether or not an update was made to the CveDB
     * @throws UpdateException is thrown if there is an error updating the
     * database
     */
    @Override
    public synchronized boolean update(Engine engine) throws UpdateException {
        this.settings = engine.getSettings();
        this.cveDb = engine.getDatabase();
        if (isUpdateConfiguredFalse()) {
            return false;
        }
        boolean updatesMade = false;
        try {
            dbProperties = cveDb.getDatabaseProperties();
            if (checkUpdate()) {
                final List<NvdCveInfo> updateable = getUpdatesNeeded();
                if (!updateable.isEmpty()) {
                    initializeExecutorServices();
                    performUpdate(updateable);
                    updatesMade = true;
                }
                //all dates in the db are now stored in seconds as opposed to previously milliseconds.
                dbProperties.save(DatabaseProperties.LAST_CHECKED, Long.toString(System.currentTimeMillis() / 1000));
            }
        } catch (UpdateException ex) {
            if (ex.getCause() != null && ex.getCause() instanceof DownloadFailedException) {
                final String jre = System.getProperty("java.version");
                if (jre == null || jre.startsWith("1.4") || jre.startsWith("1.5") || jre.startsWith("1.6") || jre.startsWith("1.7")) {
                    LOGGER.error("An old JRE is being used ({} {}), and likely does not have the correct root certificates or algorithms "
                            + "to connect to the NVD - consider upgrading your JRE.", System.getProperty("java.vendor"), jre);
                }
            }
            throw ex;
        } catch (DatabaseException ex) {
            throw new UpdateException("Database Exception, unable to update the data to use the most current data.", ex);
        } finally {
            shutdownExecutorServices();
        }
        return updatesMade;
    }

    /**
     * Checks if the system is configured NOT to update.
     *
     * @return false if the system is configured to perform an update; otherwise
     * true
     */
    private boolean isUpdateConfiguredFalse() {
        if (!settings.getBoolean(Settings.KEYS.UPDATE_NVDCVE_ENABLED, true)) {
            return true;
        }
        boolean autoUpdate = true;
        try {
            autoUpdate = settings.getBoolean(Settings.KEYS.AUTO_UPDATE);
        } catch (InvalidSettingException ex) {
            LOGGER.debug("Invalid setting for auto-update; using true.");
        }
        return !autoUpdate;
    }

    /**
     * Initialize the executor services for download and processing of the NVD
     * CVE XML data.
     */
    protected void initializeExecutorServices() {
        final int downloadPoolSize;
        final int max = settings.getInt(Settings.KEYS.MAX_DOWNLOAD_THREAD_POOL_SIZE, 1);
        if (DOWNLOAD_THREAD_POOL_SIZE > max) {
            downloadPoolSize = max;
        } else {
            downloadPoolSize = DOWNLOAD_THREAD_POOL_SIZE;
        }
        downloadExecutorService = Executors.newFixedThreadPool(downloadPoolSize);
        processingExecutorService = Executors.newFixedThreadPool(PROCESSING_THREAD_POOL_SIZE);
        LOGGER.debug("#download   threads: {}", downloadPoolSize);
        LOGGER.debug("#processing threads: {}", PROCESSING_THREAD_POOL_SIZE);
    }

    /**
     * Shutdown and cleanup of resources used by the executor services.
     */
    private void shutdownExecutorServices() {
        if (processingExecutorService != null) {
            processingExecutorService.shutdownNow();
        }
        if (downloadExecutorService != null) {
            downloadExecutorService.shutdownNow();
        }
    }

    /**
     * Checks if the NVD CVE XML files were last checked recently. As an
     * optimization, we can avoid repetitive checks against the NVD. Setting
     * CVE_CHECK_VALID_FOR_HOURS determines the duration since last check before
     * checking again. A database property stores the timestamp of the last
     * check.
     *
     * @return true to proceed with the check, or false to skip
     * @throws UpdateException thrown when there is an issue checking for
     * updates
     */
    private boolean checkUpdate() throws UpdateException {
        boolean proceed = true;
        // If the valid setting has not been specified, then we proceed to check...
        final int validForHours = settings.getInt(Settings.KEYS.CVE_CHECK_VALID_FOR_HOURS, 0);
        if (dataExists() && 0 < validForHours) {
            // ms Valid = valid (hours) x 60 min/hour x 60 sec/min x 1000 ms/sec
            final long validForSeconds = validForHours * 60L * 60L;
            final long lastChecked = getPropertyInSeconds(DatabaseProperties.LAST_CHECKED);
            final long now = System.currentTimeMillis() / 1000;
            proceed = (now - lastChecked) > validForSeconds;
            if (!proceed) {
                LOGGER.info("Skipping NVD check since last check was within {} hours.", validForHours);
                LOGGER.debug("Last NVD was at {}, and now {} is within {} s.", lastChecked, now, validForSeconds);
            }
        }
        return proceed;
    }

    /**
     * Checks the CVE Index to ensure data exists and analysis can continue.
     *
     * @return true if the database contains data
     */
    private boolean dataExists() {
        return cveDb.dataExists();
    }

    /**
     * Downloads the latest NVD CVE XML file from the web and imports it into
     * the current CVE Database.
     *
     * @param updateable a collection of NVD CVE data file references that need
     * to be downloaded and processed to update the database
     * @throws UpdateException is thrown if there is an error updating the
     * database
     */
    @SuppressWarnings("FutureReturnValueIgnored")
    private void performUpdate(List<NvdCveInfo> updateable) throws UpdateException {
        if (updateable.isEmpty()) {
            return;
        }
        if (updateable.size() > 3) {
            LOGGER.info("NVD CVE requires several updates; this could take a couple of minutes.");
        }

        DownloadTask runLast = null;
        final Set<Future<Future<ProcessTask>>> downloadFutures = new HashSet<>(updateable.size());
        for (NvdCveInfo cve : updateable) {
            final DownloadTask call = new DownloadTask(cve, processingExecutorService, cveDb, settings);
            if (call.isModified()) {
                runLast = call;
            } else {
                final boolean added = downloadFutures.add(downloadExecutorService.submit(call));
                if (!added) {
                    throw new UpdateException("Unable to add the download task for " + cve.getId());
                }
            }
        }

        //next, move the future future processTasks to just future processTasks and check for errors.
        final Set<Future<ProcessTask>> processFutures = new HashSet<>(updateable.size());
        for (Future<Future<ProcessTask>> future : downloadFutures) {
            final Future<ProcessTask> task;
            try {
                task = future.get();
                if (task != null) {
                    processFutures.add(task);
                }
            } catch (InterruptedException ex) {
                LOGGER.debug("Thread was interrupted during download", ex);
                Thread.currentThread().interrupt();
                throw new UpdateException("The download was interrupted", ex);
            } catch (ExecutionException ex) {
                LOGGER.debug("Thread was interrupted during download execution", ex);
                throw new UpdateException("The execution of the download was interrupted", ex);
            }
        }

        for (Future<ProcessTask> future : processFutures) {
            try {
                final ProcessTask task = future.get();
                if (task.getException() != null) {
                    throw task.getException();
                }
            } catch (InterruptedException ex) {
                LOGGER.debug("Thread was interrupted during processing", ex);
                Thread.currentThread().interrupt();
                throw new UpdateException(ex);
            } catch (ExecutionException ex) {
                LOGGER.debug("Execution Exception during process", ex);
                throw new UpdateException(ex);
            }
        }

        if (runLast != null) {
            final Future<Future<ProcessTask>> modified = downloadExecutorService.submit(runLast);
            final Future<ProcessTask> task;
            try {
                task = modified.get();
                if (task != null) {
                    final ProcessTask last = task.get();
                    if (last.getException() != null) {
                        throw last.getException();
                    }
                }
            } catch (InterruptedException ex) {
                LOGGER.debug("Thread was interrupted during download", ex);
                Thread.currentThread().interrupt();
                throw new UpdateException("The download was interrupted", ex);
            } catch (ExecutionException ex) {
                LOGGER.debug("Thread was interrupted during download execution", ex);
                throw new UpdateException("The execution of the download was interrupted", ex);
            }
        }

        try {
            cveDb.cleanupDatabase();
        } catch (DatabaseException ex) {
            throw new UpdateException(ex.getMessage(), ex.getCause());
        }
    }

    /**
     * Downloads the NVD CVE Meta file properties.
     *
     * @param url the URL to the NVD CVE JSON file
     * @return the meta file properties
     * @throws UpdateException thrown if the meta file could not be downloaded
     */
    protected final MetaProperties getMetaFile(String url) throws UpdateException {
        try {
            final long waitTime = settings.getInt(Settings.KEYS.CVE_DOWNLOAD_WAIT_TIME, 4000);
            MetaProperties retVal = doMetaDownload(url, false);

            final int downloadAttempts = 4;
            for (int x = 2; retVal == null && x <= downloadAttempts; x++) {
                Thread.sleep(waitTime * (x / 2));
                retVal = doMetaDownload(url, x == downloadAttempts);
            }
            return retVal;
        } catch (InterruptedException ex) {
            Thread.interrupted();
            throw new UpdateException("Download interupted", ex);
        }
    }

    /**
     * Downloads the NVD CVE Meta file properties.
     *
     * @param url the URL to the NVD CVE JSON file
     * @param throwErrors if <code>true</code> and an error occurs, the error
     * will be thrown; otherwise the error will be suppressed
     * @return the meta file properties
     * @throws UpdateException thrown if the meta file could not be downloaded
     */
    private MetaProperties doMetaDownload(String url, boolean throwErrors) throws UpdateException {
        final String metaUrl = url.substring(0, url.length() - 7) + "meta";
        final NvdCache cache = new NvdCache(settings);
        try {
            final URL u = new URL(metaUrl);
            final File tmp = settings.getTempFile("nvd", "meta");
            if (cache.notInCache(u, tmp)) {
                final Downloader d = new Downloader(settings);
                final String content = d.fetchContent(u, true, Settings.KEYS.CVE_USER, Settings.KEYS.CVE_PASSWORD);
                try (FileOutputStream fos = new FileOutputStream(tmp);
                        OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
                        BufferedWriter writer = new BufferedWriter(osw)) {
                    writer.write(content);
                }
                cache.storeInCache(u, tmp);
                FileUtils.deleteQuietly(tmp);
                return new MetaProperties(content);
            } else {
                final String content;
                try (FileInputStream fis = new FileInputStream(tmp);
                        InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
                        BufferedReader reader = new BufferedReader(isr)) {
                    content = reader.lines().collect(Collectors.joining("\n"));
                }
                FileUtils.deleteQuietly(tmp);
                return new MetaProperties(content);
            }
        } catch (MalformedURLException ex) {
            if (throwErrors) {
                throw new UpdateException("Meta file url is invalid: " + metaUrl, ex);
            }
        } catch (InvalidDataException ex) {
            if (throwErrors) {
                throw new UpdateException("Meta file content is invalid: " + metaUrl, ex);
            }
        } catch (DownloadFailedException ex) {
            if (throwErrors) {
                throw new UpdateException("Unable to download meta file: " + metaUrl, ex);
            }
        } catch (TooManyRequestsException ex) {
            if (throwErrors) {
                throw new UpdateException("Unable to download meta file: " + metaUrl + "; received 429 -- too many requests", ex);
            }
        } catch (ResourceNotFoundException ex) {
            if (throwErrors) {
                throw new UpdateException("Unable to download meta file: " + metaUrl + "; received 404 -- resource not found", ex);
            }
        } catch (IOException ex) {
            if (throwErrors) {
                throw new RuntimeException(ex);
            }
        }
        return null;
    }

    /**
     * Determines if the index needs to be updated. This is done by fetching the
     * NVD CVE meta data and checking the last update date. If the data needs to
     * be refreshed this method will return the NvdCveUrl for the files that
     * need to be updated.
     *
     * @return the collection of files that need to be updated
     * @throws UpdateException Is thrown if there is an issue with the last
     * updated properties file
     */
    protected final List<NvdCveInfo> getUpdatesNeeded() throws UpdateException {
        LOGGER.debug("starting getUpdatesNeeded() ...");
        final List<NvdCveInfo> updates = new ArrayList<>();
        if (dbProperties != null && !dbProperties.isEmpty()) {
            try {
                final int startYear = settings.getInt(Settings.KEYS.CVE_START_YEAR, 2002);
                final int endYear = Calendar.getInstance().get(Calendar.YEAR);
                boolean needsFullUpdate = false;
                for (int y = startYear; y <= endYear; y++) {
                    final long val = Long.parseLong(dbProperties.getProperty(DatabaseProperties.LAST_UPDATED_BASE + y, "0"));
                    if (val == 0) {
                        needsFullUpdate = true;
                        break;
                    }
                }
                final long lastUpdated = getPropertyInSeconds(DatabaseProperties.LAST_UPDATED);
                final long now = System.currentTimeMillis() / 1000;
                final int days = settings.getInt(Settings.KEYS.CVE_MODIFIED_VALID_FOR_DAYS, 7);

                String url = settings.getString(Settings.KEYS.CVE_MODIFIED_JSON);
                final MetaProperties modified = getMetaFile(url);

                if (!needsFullUpdate && lastUpdated == modified.getLastModifiedDate()) {
                    return updates;
                } else {
                    final int start = settings.getInt(Settings.KEYS.CVE_START_YEAR);
                    final int end = Calendar.getInstance().get(Calendar.YEAR);
                    final String baseUrl = settings.getString(Settings.KEYS.CVE_BASE_JSON);
                    final NvdCveInfo item = new NvdCveInfo(MODIFIED, url, modified.getLastModifiedDate());
                    updates.add(item);
                    if (needsFullUpdate) {
                        // no need to download each one, just use the modified timestamp
                        for (int i = start; i <= end; i++) {
                            url = String.format(baseUrl, i);
                            final NvdCveInfo entry = new NvdCveInfo(Integer.toString(i), url, modified.getLastModifiedDate());
                            updates.add(entry);
                        }
                    } else if (!DateUtil.withinDateRange(lastUpdated, now, days)) {
                        final long waitTime = settings.getInt(Settings.KEYS.CVE_DOWNLOAD_WAIT_TIME, 4000);
                        for (int i = start; i <= end; i++) {
                            try {
                                url = String.format(baseUrl, i);
                                Thread.sleep(waitTime);
                                final MetaProperties meta = getMetaFile(url);
                                final long currentTimestamp = getPropertyInSeconds(DatabaseProperties.LAST_UPDATED_BASE + i);

                                if (currentTimestamp < meta.getLastModifiedDate()) {
                                    final NvdCveInfo entry = new NvdCveInfo(Integer.toString(i), url, meta.getLastModifiedDate());
                                    updates.add(entry);
                                }
                            } catch (UpdateException ex) {
                                final Calendar date = Calendar.getInstance();
                                final int year = date.get(Calendar.YEAR);
                                final int month = date.get(Calendar.MONTH);
                                final int day = date.get(Calendar.DATE);
                                final int grace = settings.getInt(Settings.KEYS.NVD_NEW_YEAR_GRACE_PERIOD, 10);
                                if (ex.getMessage().contains("Unable to download meta file")
                                        && i == year && month == 0 && day < grace) {
                                    LOGGER.warn("NVD Data for {} has not been published yet.", year);
                                } else {
                                    throw ex;
                                }
                            } catch (InterruptedException ex) {
                                Thread.interrupted();
                                throw new UpdateException("The download of the meta file was interupted: " + url, ex);
                            }
                        }
                    }
                }
            } catch (NumberFormatException ex) {
                LOGGER.warn("An invalid schema version or timestamp exists in the data.properties file.");
                LOGGER.debug("", ex);
            } catch (InvalidSettingException ex) {
                throw new UpdateException("The NVD CVE start year property is set to an invalid value", ex);
            }
        }
        return updates;
    }

    /**
     * Returns the database property value in seconds.
     *
     * @param key the key to the property
     * @return the property value in seconds
     */
    private long getPropertyInSeconds(String key) {
        final String value = dbProperties.getProperty(key, "0");
        return DateUtil.getEpochValueInSeconds(value);
    }

    /**
     * Sets the settings object; this is used during testing.
     *
     * @param settings the configured settings
     */
    protected synchronized void setSettings(Settings settings) {
        this.settings = settings;
    }

    @Override
    public boolean purge(Engine engine) {
        boolean result = true;
        try {
            final File dataDir = engine.getSettings().getDataDirectory();
            final File db = new File(dataDir, engine.getSettings().getString(Settings.KEYS.DB_FILE_NAME, "odc.mv.db"));
            if (db.exists()) {
                if (db.delete()) {
                    LOGGER.info("Database file purged; local copy of the NVD has been removed");
                } else {
                    LOGGER.error("Unable to delete '{}'; please delete the file manually", db.getAbsolutePath());
                    result = false;
                }
            } else {
                LOGGER.info("Unable to purge database; the database file does not exist: {}", db.getAbsolutePath());
                result = false;
            }
            final File traceFile = new File(dataDir, "odc.trace.db");
            if (traceFile.exists() && !traceFile.delete()) {
                LOGGER.error("Unable to delete '{}'; please delete the file manually", traceFile.getAbsolutePath());
                result = false;
            }
            final File lockFile = new File(dataDir, "odc.update.lock");
            if (lockFile.exists() && !lockFile.delete()) {
                LOGGER.error("Unable to delete '{}'; please delete the file manually", lockFile.getAbsolutePath());
                result = false;
            }
        } catch (IOException ex) {
            final String msg = "Unable to delete the database";
            LOGGER.error(msg, ex);
            result = false;
        }
        return result;
    }
}
