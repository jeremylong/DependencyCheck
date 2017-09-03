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
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import javax.annotation.concurrent.ThreadSafe;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

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
     * A reference to the CveDB.
     */
    private final CveDB cveDB;
    /**
     * A reference to the callable download task.
     */
    private final DownloadTask filePair;
    /**
     * A reference to the properties.
     */
    private final DatabaseProperties properties;
    /**
     * A reference to the global settings object.
     */
    private final Settings settings;

    /**
     * Constructs a new ProcessTask used to process an NVD CVE update.
     *
     * @param cveDB the data store object
     * @param filePair the download task that contains the URL references to
     * download
     * @param settings a reference to the global settings object; this is
     * necessary so that when the thread is started the dependencies have a
     * correct reference to the global settings.
     */
    public ProcessTask(final CveDB cveDB, final DownloadTask filePair, Settings settings) {
        this.cveDB = cveDB;
        this.filePair = filePair;
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
     * Imports the NVD CVE XML File into the Lucene Index.
     *
     * @param file the file containing the NVD CVE XML
     * @param oldVersion contains the file containing the NVD CVE XML 1.2
     * @throws ParserConfigurationException is thrown if there is a parser
     * configuration exception
     * @throws SAXException is thrown if there is a SAXException
     * @throws IOException is thrown if there is a IO Exception
     * @throws SQLException is thrown if there is a SQL exception
     * @throws DatabaseException is thrown if there is a database exception
     * @throws ClassNotFoundException thrown if the h2 database driver cannot be
     * loaded
     */
    protected void importXML(File file, File oldVersion) throws ParserConfigurationException,
            SAXException, IOException, SQLException, DatabaseException, ClassNotFoundException {

        final SAXParser saxParser = XmlUtils.buildSecureSaxParser();

        final NvdCve12Handler cve12Handler = new NvdCve12Handler();
        saxParser.parse(oldVersion, cve12Handler);
        final Map<String, List<VulnerableSoftware>> prevVersionVulnMap = cve12Handler.getVulnerabilities();

        final NvdCve20Handler cve20Handler = new NvdCve20Handler();
        cve20Handler.setCveDB(cveDB);
        cve20Handler.setPrevVersionVulnMap(prevVersionVulnMap);
        saxParser.parse(file, cve20Handler);
    }

    /**
     * Processes the NVD CVE XML file and imports the data into the DB.
     *
     * @throws UpdateException thrown if there is an error loading the data into
     * the database
     */
    private void processFiles() throws UpdateException {
        LOGGER.info("Processing Started for NVD CVE - {}", filePair.getNvdCveInfo().getId());
        final long startProcessing = System.currentTimeMillis();
        try {
            importXML(filePair.getFirst(), filePair.getSecond());
            cveDB.commit();
            properties.save(filePair.getNvdCveInfo());
        } catch (ParserConfigurationException | SAXException | SQLException | DatabaseException | ClassNotFoundException | IOException ex) {
            throw new UpdateException(ex);
        } finally {
            filePair.cleanup();
        }
        LOGGER.info("Processing Complete for NVD CVE - {}  ({} ms)", filePair.getNvdCveInfo().getId(),
                System.currentTimeMillis() - startProcessing);
    }
}
