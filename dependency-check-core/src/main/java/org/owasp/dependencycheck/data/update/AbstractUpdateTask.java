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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.owasp.dependencycheck.data.UpdateException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.NvdCve12Handler;
import org.owasp.dependencycheck.data.nvdcve.NvdCve20Handler;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.DownloadFailedException;
import org.xml.sax.SAXException;

/**
 * Class responsible for updating the CPE and NVDCVE data stores.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public abstract class AbstractUpdateTask implements UpdateTask {

    /**
     * Initializes the AbstractUpdateTask.
     *
     * @param properties information about the data store
     * @throws MalformedURLException thrown if the configuration contains a
     * malformed url
     * @throws DownloadFailedException thrown if the timestamp on a file cannot
     * be checked
     * @throws UpdateException thrown if the update fails
     */
    public AbstractUpdateTask(DataStoreMetaInfo properties) throws MalformedURLException, DownloadFailedException, UpdateException {
        this.properties = properties;
        this.updateable = updatesNeeded();
    }
    /**
     * A collection of updateable NVD CVE items.
     */
    private Updateable updateable;
    /**
     * Utility to read and write meta-data about the data.
     */
    private DataStoreMetaInfo properties = null;

    /**
     * Returns the data store properties.
     *
     * @return the data store properties
     */
    protected DataStoreMetaInfo getProperties() {
        return properties;
    }
    /**
     * Reference to the Cve Database.
     */
    private CveDB cveDB = null;

    /**
     * Returns the CveDB.
     *
     * @return the CveDB
     */
    protected CveDB getCveDB() {
        return cveDB;
    }

    /**
     * Gets whether or not an update is needed.
     *
     * @return true or false depending on whether an update is needed
     */
    public boolean isUpdateNeeded() {
        return updateable.isUpdateNeeded();
    }

    /**
     * Gets the updateable NVD CVE Entries.
     *
     * @return an Updateable object containing the NVD CVE entries
     */
    protected Updateable getUpdateable() {
        return updateable;
    }

    /**
     * Determines if the index needs to be updated.
     *
     * @return a collection of updateable resources.
     * @throws MalformedURLException is thrown if the URL for the NVD CVE Meta
     * data is incorrect.
     * @throws DownloadFailedException is thrown if there is an error.
     * downloading the NVD CVE download data file.
     * @throws UpdateException Is thrown if there is an issue with the last
     * updated properties file.
     */
    protected abstract Updateable updatesNeeded() throws MalformedURLException, DownloadFailedException, UpdateException;

    /**
     * <p>Updates the data store to the latest version.</p>
     *
     * @throws UpdateException is thrown if there is an error updating the
     * database
     */
    public abstract void update() throws UpdateException;
    /**
     * A flag indicating whether or not the current data store should be
     * deleted.
     */
    private boolean deleteAndRecreate = false;

    /**
     * Get the value of deleteAndRecreate.
     *
     * @return the value of deleteAndRecreate
     */
    public boolean shouldDeleteAndRecreate() {
        return deleteAndRecreate;
    }

    /**
     * Set the value of deleteAndRecreate.
     *
     * @param deleteAndRecreate new value of deleteAndRecreate
     */
    protected void setDeleteAndRecreate(boolean deleteAndRecreate) {
        this.deleteAndRecreate = deleteAndRecreate;
    }

    /**
     * Deletes the existing data directories.
     *
     * @throws IOException thrown if the directory cannot be deleted
     */
    protected void deleteExistingData() throws IOException {
        File data = Settings.getDataFile(Settings.KEYS.CVE_DATA_DIRECTORY);
        if (data.exists()) {
            FileUtils.delete(data);
        }
        data = DataStoreMetaInfo.getPropertiesFile();
        if (data.exists()) {
            FileUtils.delete(data);
        }
    }

    /**
     * Closes the CVE and CPE data stores.
     */
    protected void closeDataStores() {
        if (cveDB != null) {
            try {
                cveDB.close();
            } catch (Exception ignore) {
                Logger.getLogger(AbstractUpdateTask.class.getName()).log(Level.FINEST, "Error closing the cveDB", ignore);
            }
        }
    }

    /**
     * Opens the CVE and CPE data stores.
     *
     * @throws UpdateException thrown if a data store cannot be opened
     */
    protected void openDataStores() throws UpdateException {
        //open the cve and cpe data stores
        try {
            cveDB = new CveDB();
            cveDB.open();
        } catch (IOException ex) {
            closeDataStores();
            Logger.getLogger(AbstractUpdateTask.class.getName()).log(Level.FINE, "IO Error opening databases", ex);
            throw new UpdateException("Error updating the CPE/CVE data, please see the log file for more details.");
        } catch (SQLException ex) {
            closeDataStores();
            Logger.getLogger(AbstractUpdateTask.class.getName()).log(Level.FINE, "SQL Exception opening databases", ex);
            throw new UpdateException("Error updating the CPE/CVE data, please see the log file for more details.");
        } catch (DatabaseException ex) {
            closeDataStores();
            Logger.getLogger(AbstractUpdateTask.class.getName()).log(Level.FINE, "Database Exception opening databases", ex);
            throw new UpdateException("Error updating the CPE/CVE data, please see the log file for more details.");
        } catch (ClassNotFoundException ex) {
            closeDataStores();
            Logger.getLogger(AbstractUpdateTask.class.getName()).log(Level.FINE, "Class not found exception opening databases", ex);
            throw new UpdateException("Error updating the CPE/CVE data, please see the log file for more details.");
        }
    }

    /**
     * Determines if the epoch date is within the range specified of the
     * compareTo epoch time. This takes the (compareTo-date)/1000/60/60/24 to
     * get the number of days. If the calculated days is less then the range the
     * date is considered valid.
     *
     * @param date the date to be checked.
     * @param compareTo the date to compare to.
     * @param range the range in days to be considered valid.
     * @return whether or not the date is within the range.
     */
    protected boolean withinRange(long date, long compareTo, int range) {
        final double differenceInDays = (compareTo - date) / 1000.0 / 60.0 / 60.0 / 24.0;
        return differenceInDays < range;
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
}
