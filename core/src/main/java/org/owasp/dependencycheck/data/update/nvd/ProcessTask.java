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
import java.sql.SQLException;
import java.util.concurrent.Callable;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.parsers.ParserConfigurationException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A callable task that will process a given set of NVD CVE xml files and update
 * the Cve Database accordingly.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class ProcessTask implements Callable<ProcessTask> {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(ProcessTask.class);
    /**
     * A field to store any update exceptions that occur during the "call".
     */
    private UpdateException exception = null;
    /**
     * A reference to the CveDB.
     */
    private final CveDB cveDB;
    /**
     * A reference to the callable download task.
     */
    private final DownloadTask downloadTask;
    /**
     * A reference to the properties.
     */
    private final DatabaseProperties properties;
    /**
     * A reference to the global settings object.
     */
    private final Settings settings;

    /**
     * Get the value of exception.
     *
     * @return the value of exception
     */
    public UpdateException getException() {
        return exception;
    }

    /**
     * Set the value of exception.
     *
     * @param exception new value of exception
     */
    public void setException(UpdateException exception) {
        this.exception = exception;
    }

    /**
     * Constructs a new ProcessTask used to process an NVD CVE update.
     *
     * @param cveDB the data store object
     * @param downloadTask the download task that contains the URL references to
     * download
     * @param settings a reference to the global settings object; this is
     * necessary so that when the thread is started the dependencies have a
     * correct reference to the global settings.
     */
    public ProcessTask(final CveDB cveDB, final DownloadTask downloadTask, Settings settings) {
        this.cveDB = cveDB;
        this.downloadTask = downloadTask;
        this.properties = cveDB.getDatabaseProperties();
        this.settings = settings;
    }

    /**
     * Implements the callable interface.
     *
     * @return this object
     * @throws Exception thrown if there is an exception; note that any
     * UpdateExceptions are simply added to the tasks exception collection
     */
    @Override
    public ProcessTask call() throws Exception {
        try {
            processFiles();
        } catch (UpdateException ex) {
            this.exception = ex;
        } finally {
            settings.cleanup(false);
        }
        return this;
    }

    /**
     * Imports the NVD CVE JSON File into the database.
     *
     * @param file the file containing the NVD CVE JSON
     * @throws ParserConfigurationException is thrown if there is a parser
     * configuration exception
     * @throws IOException is thrown if there is a IO Exception
     * @throws SQLException is thrown if there is a SQL exception
     * @throws DatabaseException is thrown if there is a database exception
     * @throws ClassNotFoundException thrown if the h2 database driver cannot be
     * loaded
     * @throws UpdateException thrown if the file could not be found
     */
    protected void importJSON(File file) throws ParserConfigurationException,
            IOException, SQLException, DatabaseException, ClassNotFoundException, UpdateException {

        final NvdCveParser parser = new NvdCveParser(settings, cveDB);
        parser.parse(file);
    }

    /**
     * Processes the NVD CVE XML file and imports the data into the DB.
     *
     * @throws UpdateException thrown if there is an error loading the data into
     * the database
     */
    private void processFiles() throws UpdateException {
        LOGGER.info("Processing Started for NVD CVE - {}", downloadTask.getNvdCveInfo().getId());
        final long startProcessing = System.currentTimeMillis();
        try {
            importJSON(downloadTask.getFile());
            properties.save(downloadTask.getNvdCveInfo());
        } catch (ParserConfigurationException | SQLException | DatabaseException | ClassNotFoundException | IOException ex) {
            throw new UpdateException(ex);
        } finally {
            downloadTask.cleanup();
        }
        LOGGER.info("Processing Complete for NVD CVE - {}  ({} ms)", downloadTask.getNvdCveInfo().getId(),
                System.currentTimeMillis() - startProcessing);
    }
}
