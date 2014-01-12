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

import org.owasp.dependencycheck.data.update.xml.NvdCve20Handler;
import org.owasp.dependencycheck.data.update.xml.NvdCve12Handler;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.update.StandardUpdate;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.xml.sax.SAXException;

/**
 * A callable task that will process a given set of NVD CVE xml files and update
 * the Cve Database accordingly.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class ProcessTask implements Callable<ProcessTask> {

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
    private final CallableDownloadTask filePair;
    /**
     * A reference to the properties.
     */
    private final DatabaseProperties properties;

    /**
     * Constructs a new ProcessTask used to process an NVD CVE update.
     *
     * @param cveDB the data store object
     * @param filePair the download task that contains the URL references to
     * download
     */
    public ProcessTask(final CveDB cveDB, final CallableDownloadTask filePair) {
        this.cveDB = cveDB;
        this.filePair = filePair;
        this.properties = cveDB.getDatabaseProperties();
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

        final SAXParserFactory factory = SAXParserFactory.newInstance();
        final SAXParser saxParser = factory.newSAXParser();

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
        String msg = String.format("Processing Started for NVD CVE - %s", filePair.getNvdCveInfo().getId());
        Logger.getLogger(StandardUpdate.class.getName()).log(Level.INFO, msg);
        try {
            importXML(filePair.getFirst(), filePair.getSecond());
            cveDB.commit();
            properties.save(filePair.getNvdCveInfo());
        } catch (FileNotFoundException ex) {
            throw new UpdateException(ex);
        } catch (ParserConfigurationException ex) {
            throw new UpdateException(ex);
        } catch (SAXException ex) {
            throw new UpdateException(ex);
        } catch (IOException ex) {
            throw new UpdateException(ex);
        } catch (SQLException ex) {
            throw new UpdateException(ex);
        } catch (DatabaseException ex) {
            throw new UpdateException(ex);
        } catch (ClassNotFoundException ex) {
            throw new UpdateException(ex);
        } finally {
            filePair.cleanup();
        }
        msg = String.format("Processing Complete for NVD CVE - %s", filePair.getNvdCveInfo().getId());
        Logger.getLogger(StandardUpdate.class.getName()).log(Level.INFO, msg);
    }
}
