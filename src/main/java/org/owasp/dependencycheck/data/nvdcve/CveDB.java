/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Check. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.data.cpe.Entry;
import org.owasp.dependencycheck.data.cwe.CweDB;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;

/**
 * The database holding information about the NVD CVE data.
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public class CveDB {

    //<editor-fold defaultstate="collapsed" desc="Constants to create, maintain, and retrieve data from the CVE Database">
    /**
     * SQL Statement to create an index on the reference table.
     */
    public static final String CREATE_INDEX_IDXREFERENCE = "CREATE INDEX IF NOT EXISTS idxReference ON reference(cveid)";
    /**
     * SQL Statement to create an index on the software for finding CVE entries based on CPE data.
     */
    public static final String CREATE_INDEX_IDXSOFTWARE = "CREATE INDEX IF NOT EXISTS idxSoftware ON software(product, vendor, version)";
    /**
     * SQL Statement to create an index for retrieving software by CVEID.
     */
    public static final String CREATE_INDEX_IDXSOFTWARECVE = "CREATE INDEX IF NOT EXISTS idxSoftwareCve ON software(cveid)";
    /**
     * SQL Statement to create an index on the vulnerability table.
     */
    public static final String CREATE_INDEX_IDXVULNERABILITY = "CREATE INDEX IF NOT EXISTS idxVulnerability ON vulnerability(cveid)";
    /**
     * SQL Statement to create the reference table.
     */
    public static final String CREATE_TABLE_REFERENCE = "CREATE TABLE IF NOT EXISTS reference (cveid CHAR(13), "
            + "name varchar(1000), url varchar(1000), source varchar(255))";
    /**
     * SQL Statement to create the software table.
     */
    public static final String CREATE_TABLE_SOFTWARE = "CREATE TABLE IF NOT EXISTS software (cveid CHAR(13), cpe varchar(500), "
            + "vendor varchar(255), product varchar(255), version varchar(50), previousVersion varchar(50))";
    /**
     * SQL Statement to create the vulnerability table.
     */
    public static final String CREATE_TABLE_VULNERABILITY = "CREATE TABLE IF NOT EXISTS vulnerability (cveid CHAR(13) PRIMARY KEY, "
            + "description varchar(8000), cwe varchar(10), cvssScore DECIMAL(3,1), cvssAccessVector varchar(20), "
            + "cvssAccessComplexity varchar(20), cvssAuthentication varchar(20), cvssConfidentialityImpact varchar(20), "
            + "cvssIntegrityImpact varchar(20), cvssAvailabilityImpact varchar(20))";
    /**
     * SQL Statement to delete references by CVEID.
     */
    public static final String DELETE_REFERENCE = "DELETE FROM reference WHERE cveid = ?";
    /**
     * SQL Statement to delete software by CVEID.
     */
    public static final String DELETE_SOFTWARE = "DELETE FROM software WHERE cveid = ?";
    /**
     * SQL Statement to delete a vulnerability by CVEID.
     */
    public static final String DELETE_VULNERABILITY = "DELETE FROM vulnerability WHERE cveid = ?";
    /**
     * SQL Statement to insert a new reference.
     */
    public static final String INSERT_REFERENCE = "INSERT INTO reference (cveid, name, url, source) VALUES (?, ?, ?, ?)";
    /**
     * SQL Statement to insert a new software.
     */
    public static final String INSERT_SOFTWARE = "INSERT INTO software (cveid, cpe, vendor, product, version, previousVersion) "
            + "VALUES (?, ?, ?, ?, ?, ?)";
    /**
     * SQL Statement to insert a new vulnerability.
     */
    public static final String INSERT_VULNERABILITY = "INSERT INTO vulnerability (cveid, description, cwe, cvssScore, cvssAccessVector, "
            + "cvssAccessComplexity, cvssAuthentication, cvssConfidentialityImpact, cvssIntegrityImpact, cvssAvailabilityImpact) "
            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    /**
     * SQL Statement to find CVE entries based on CPE data.
     */
    public static final String SELECT_CVE_FROM_SOFTWARE = "SELECT cveid FROM software WHERE Vendor = ? AND Product = ? AND "
            + "(version = '-' OR previousVersion IS NOT NULL OR version=?)";
    /**
     * SQL Statement to select references by CVEID.
     */
    public static final String SELECT_REFERENCE = "SELECT source, name, url FROM reference WHERE cveid = ?";
    /**
     * SQL Statement to select software by CVEID.
     */
    public static final String SELECT_SOFTWARE = "SELECT cpe, previousVersion FROM software WHERE cveid = ?";
    /**
     * SQL Statement to select a vulnerability by CVEID.
     */
    public static final String SELECT_VULNERABILITY = "SELECT cveid, description, cwe, cvssScore, cvssAccessVector, cvssAccessComplexity, "
            + "cvssAuthentication, cvssConfidentialityImpact, cvssIntegrityImpact, cvssAvailabilityImpact FROM vulnerability WHERE cveid = ?";
    //</editor-fold>
    //<editor-fold defaultstate="collapsed" desc="Collection of CallableStatements to work with the DB">
    /**
     * delete reference - parameters (cveid).
     */
    private CallableStatement deleteReferences;
    /**
     * delete software - parameters (cveid).
     */
    private CallableStatement deleteSoftware;
    /**
     * delete vulnerability - parameters (cveid).
     */
    private CallableStatement deleteVulnerabilities;
    /**
     * insert reference - parameters (cveid, name, url, source).
     */
    private CallableStatement insertReference;
    /**
     * insert software - parameters (cveid, cpe, vendor, product, version, previousVersion).
     */
    private CallableStatement insertSoftware;
    /**
     * insert vulnerability - parameters (cveid, description, cwe, cvssScore, cvssAccessVector,
     * cvssAccessComplexity, cvssAuthentication, cvssConfidentialityImpact, cvssIntegrityImpact, cvssAvailabilityImpact).
     */
    private CallableStatement insertVulnerability;
    /**
     * select cve from software - parameters (vendor, product, version).
     */
    private CallableStatement selectCveFromSoftware;
    /**
     * select vulnerability - parameters (cveid).
     */
    private CallableStatement selectVulnerability;
    /**
     * select reference - parameters (cveid).
     */
    private CallableStatement selectReferences;
    /**
     * select software - parameters (cveid).
     */
    private CallableStatement selectSoftware;
    //</editor-fold>
    /**
     * Database connection
     */
    private Connection conn;

    /**
     * Opens the database connection. If the database does not exist, it will
     * create a new one.
     *
     * @throws IOException thrown if there is an IO Exception
     * @throws SQLException thrown if there is a SQL Exception
     * @throws DatabaseException thrown if there is an error initializing a new database
     * @throws ClassNotFoundException thrown if the h2 database driver cannot be loaded
     */
    @edu.umd.cs.findbugs.annotations.SuppressWarnings(
    value = "DMI_EMPTY_DB_PASSWORD",
    justification = "Yes, I know... Blank password.")
    public void open() throws IOException, SQLException, DatabaseException, ClassNotFoundException {
        final String fileName = CveDB.getDataDirectory().getCanonicalPath()
                + File.separator
                + "cve";
        final File f = new File(fileName);
        final boolean createTables = !f.exists();
        final String connStr = "jdbc:h2:file:" + fileName;
        Class.forName("org.h2.Driver");
        conn = DriverManager.getConnection(connStr, "sa", "");
        if (createTables) {
            createTables();
        }
        buildStatements();
    }

    /**
     * Cleans up the object and ensures that "close" has been called.
     * @throws Throwable thrown if there is a problem
     */
    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize(); //not necessary if extending Object.
    }

    /**
     * Closes the DB4O database. Close should be called on
     * this object when it is done being used.
     */
    public void close() {
        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException ex) {
                final String msg = "There was an error attempting to close the CveDB, see the log for more details.";
                Logger.getLogger(CveDB.class.getName()).log(Level.SEVERE, msg, ex);
                Logger.getLogger(CveDB.class.getName()).log(Level.FINE, null, ex);
            }
            conn = null;
        }
    }

    /**
     * Retrieves the vulnerabilities associated with the specified CPE.
     *
     * @param cpeStr the CPE name
     * @return a list of Vulnerabilities
     * @throws DatabaseException thrown if there is an exception retrieving data
     */
    public List<Vulnerability> getVulnerabilities(String cpeStr) throws DatabaseException {
        ResultSet rs = null;
        final Entry cpe = new Entry();
        try {
            cpe.parseName(cpeStr);
        } catch (UnsupportedEncodingException ex) {
            final String msg = "There was an encoding error parsing a vulerability, see the log for more details.";
            Logger.getLogger(CveDB.class.getName()).log(Level.WARNING, msg);
            Logger.getLogger(CveDB.class.getName()).log(Level.FINE, String.format("Error parsing '%s'", cpeStr), ex);
        }
        final List<Vulnerability> vulnerabilities = new ArrayList<Vulnerability>();

        try {
            selectCveFromSoftware.setString(1, cpe.getVendor());
            selectCveFromSoftware.setString(2, cpe.getProduct());
            selectCveFromSoftware.setString(3, cpe.getVersion());
            rs = selectCveFromSoftware.executeQuery();
            while (rs.next()) {
                final Vulnerability v = getVulnerability(rs.getString("cveid"));
                vulnerabilities.add(v);
            }
        } catch (SQLException ex) {
            throw new DatabaseException("Exception retrieving vulnerability for " + cpeStr, ex);
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException ex) {
                    Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Error closing RecordSet", ex);
                }
            }
        }
        return vulnerabilities;
    }

    /**
     * Gets a vulnerability for the provided CVE.
     *
     * @param cve the CVE to lookup
     * @return a vulnerability object
     * @throws DatabaseException if an exception occurs
     */
    private Vulnerability getVulnerability(String cve) throws DatabaseException {
        ResultSet rsV = null;
        ResultSet rsR = null;
        ResultSet rsS = null;
        Vulnerability vuln = null;
        try {
            selectVulnerability.setString(1, cve);
            rsV = selectVulnerability.executeQuery();
            if (rsV.next()) {
                vuln = new Vulnerability();
                vuln.setName(cve);
                vuln.setDescription(rsV.getString(2));
                String cwe = rsV.getString(3);
                if (cwe != null) {
                    final String name = CweDB.getCweName(cwe);
                    if (name != null) {
                        cwe += " " + name;
                    }
                }
                vuln.setCwe(cwe);
                vuln.setCvssScore(rsV.getFloat(4));
                vuln.setCvssAccessVector(rsV.getString(5));
                vuln.setCvssAccessComplexity(rsV.getString(6));
                vuln.setCvssAuthentication(rsV.getString(7));
                vuln.setCvssConfidentialityImpact(rsV.getString(8));
                vuln.setCvssIntegrityImpact(rsV.getString(9));
                vuln.setCvssAvailabilityImpact(rsV.getString(10));

                selectReferences.setString(1, cve);
                rsR = selectReferences.executeQuery();
                while (rsR.next()) {
                    vuln.addReference(rsR.getString(1), rsR.getString(2), rsR.getString(3));
                }
                selectSoftware.setString(1, cve);
                rsS = selectSoftware.executeQuery();
                while (rsS.next()) {
                    final String cpe = rsS.getString(1);
                    final String prevVersion = rsS.getString(2);
                    if (prevVersion == null) {
                        vuln.addVulnerableSoftware(cpe);
                    } else {
                        vuln.addVulnerableSoftware(cpe, prevVersion);
                    }
                }
            }
        } catch (SQLException ex) {
            throw new DatabaseException("Error retrieving " + cve, ex);
        } finally {
            if (rsV != null) {
                try {
                    rsV.close();
                } catch (SQLException ex) {
                    Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Error closing RecordSet", ex);
                }
            }
            if (rsR != null) {
                try {
                    rsR.close();
                } catch (SQLException ex) {
                    Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Error closing RecordSet", ex);
                }
            }
            if (rsS != null) {
                try {
                    rsS.close();
                } catch (SQLException ex) {
                    Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Error closing RecordSet", ex);
                }
            }
        }
        return vuln;
    }

    /**
     * Updates the vulnerability within the database. If the vulnerability does not
     * exist it will be added.
     *
     * @param vuln the vulnerability to add to the database
     * @throws DatabaseException is thrown if the database
     */
    public void updateVulnerability(Vulnerability vuln) throws DatabaseException {
        try {
            // first delete any existing vulnerability info.
            deleteReferences.setString(1, vuln.getName());
            deleteReferences.execute();
            deleteSoftware.setString(1, vuln.getName());
            deleteSoftware.execute();
            deleteVulnerabilities.setString(1, vuln.getName());
            deleteVulnerabilities.execute();

            insertVulnerability.setString(1, vuln.getName());
            insertVulnerability.setString(2, vuln.getDescription());
            insertVulnerability.setString(3, vuln.getCwe());
            insertVulnerability.setFloat(4, vuln.getCvssScore());
            insertVulnerability.setString(5, vuln.getCvssAccessVector());
            insertVulnerability.setString(6, vuln.getCvssAccessComplexity());
            insertVulnerability.setString(7, vuln.getCvssAuthentication());
            insertVulnerability.setString(8, vuln.getCvssConfidentialityImpact());
            insertVulnerability.setString(9, vuln.getCvssIntegrityImpact());
            insertVulnerability.setString(10, vuln.getCvssAvailabilityImpact());
            insertVulnerability.execute();

            insertReference.setString(1, vuln.getName());
            for (Reference r : vuln.getReferences()) {
                insertReference.setString(2, r.getName());
                insertReference.setString(3, r.getUrl());
                insertReference.setString(4, r.getSource());
                insertReference.execute();
            }
            insertSoftware.setString(1, vuln.getName());
            for (VulnerableSoftware s : vuln.getVulnerableSoftware()) {
                //cveid, cpe, vendor, product, version, previousVersion
                insertSoftware.setString(2, s.getName());
                insertSoftware.setString(3, s.getVendor());
                insertSoftware.setString(4, s.getProduct());
                insertSoftware.setString(5, s.getVersion());
                if (s.hasPreviousVersion()) {
                    insertSoftware.setString(6, s.getPreviousVersion());
                } else {
                    insertSoftware.setNull(6, java.sql.Types.VARCHAR);
                }
                insertSoftware.execute();
            }

        } catch (SQLException ex) {
            final String msg = String.format("Error updating '%s'", vuln.getName());
            Logger.getLogger(CveDB.class.getName()).log(Level.INFO, null, ex);
            throw new DatabaseException(msg, ex);
        }
    }

    /**
     * Retrieves the directory that the JAR file exists in so that
     * we can ensure we always use a common data directory.
     *
     * @return the data directory for this index.
     * @throws IOException is thrown if an IOException occurs of course...
     */
    public static File getDataDirectory() throws IOException {
        final String fileName = Settings.getString(Settings.KEYS.CVE_INDEX);
        final File path = FileUtils.getDataDirectory(fileName, CveDB.class);
        if (!path.exists()) {
            if (!path.mkdirs()) {
                throw new IOException("Unable to create NVD CVE Data directory");
            }
        }
        return path;
    }

    /**
     * Creates the database structure (tables and indexes) to store the CVE data
     *
     * @throws SQLException thrown if there is a sql exception
     * @throws DatabaseException thrown if there is a database exception
     */
    protected void createTables() throws SQLException, DatabaseException {
        Statement statement = null;
        try {
            statement = conn.createStatement();
            statement.execute(CREATE_TABLE_VULNERABILITY);
            statement.execute(CREATE_TABLE_REFERENCE);
            statement.execute(CREATE_TABLE_SOFTWARE);
            statement.execute(CREATE_INDEX_IDXSOFTWARE);
            statement.execute(CREATE_INDEX_IDXREFERENCE);
            statement.execute(CREATE_INDEX_IDXVULNERABILITY);
            statement.execute(CREATE_INDEX_IDXSOFTWARECVE);
        } finally {
            if (statement != null) {
                try {
                    statement.close();
                } catch (SQLException ex) {
                    Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Error closing Statement", ex);
                }
            }
        }
    }

    /**
     * Builds the CallableStatements used by the application.
     * @throws DatabaseException thrown if there is a database exception
     */
    private void buildStatements() throws DatabaseException {
        try {
            deleteReferences = conn.prepareCall(DELETE_REFERENCE);
            deleteSoftware = conn.prepareCall(DELETE_SOFTWARE);
            deleteVulnerabilities = conn.prepareCall(DELETE_VULNERABILITY);
            insertReference = conn.prepareCall(INSERT_REFERENCE);
            insertSoftware = conn.prepareCall(INSERT_SOFTWARE);
            insertVulnerability = conn.prepareCall(INSERT_VULNERABILITY);
            selectCveFromSoftware = conn.prepareCall(SELECT_CVE_FROM_SOFTWARE);
            selectVulnerability = conn.prepareCall(SELECT_VULNERABILITY);
            selectReferences = conn.prepareCall(SELECT_REFERENCE);
            selectSoftware = conn.prepareCall(SELECT_SOFTWARE);
        } catch (SQLException ex) {
            throw new DatabaseException("Unable to prepare statements", ex);
        }

    }
}
