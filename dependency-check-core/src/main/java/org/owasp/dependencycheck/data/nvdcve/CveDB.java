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
package org.owasp.dependencycheck.data.nvdcve;

import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.utils.DBUtils;
import org.owasp.dependencycheck.data.cwe.CweDB;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;

/**
 * The database holding information about the NVD CVE data.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class CveDB {

    /**
     * Database connection
     */
    private Connection conn;

    /**
     * Creates a new CveDB object and opens the database connection. Note, the
     * connection must be closed by the caller by calling the close method.
     *
     * @throws DatabaseException thrown if there is an exception opening the
     * database.
     */
    public CveDB() throws DatabaseException {
        super();
        try {
            open();
            databaseProperties = new DatabaseProperties(this);
        } catch (DatabaseException ex) {
            throw ex;
        }
    }

    /**
     * Returns the database connection.
     *
     * @return the database connection
     */
    protected Connection getConnection() {
        return conn;
    }

    /**
     * Opens the database connection. If the database does not exist, it will
     * create a new one.
     *
     * @throws DatabaseException thrown if there is an error opening the
     * database connection
     */
    public final void open() throws DatabaseException {
        conn = ConnectionFactory.getConnection();
    }

    /**
     * Closes the DB4O database. Close should be called on this object when it
     * is done being used.
     */
    public void close() {
        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException ex) {
                final String msg = "There was an error attempting to close the CveDB, see the log for more details.";
                Logger.getLogger(DBUtils.class.getName()).log(Level.SEVERE, msg);
                Logger.getLogger(DBUtils.class.getName()).log(Level.FINE, null, ex);
            }
            conn = null;
        }
    }

    /**
     * Returns whether the database connection is open or closed.
     *
     * @return whether the database connection is open or closed
     */
    public boolean isOpen() {
        return conn != null;
    }

    /**
     * Commits all completed transactions.
     *
     * @throws SQLException thrown if a SQL Exception occurs
     */
    public void commit() throws SQLException {
        if (conn != null) {
            conn.commit();
        }
    }

    /**
     * Cleans up the object and ensures that "close" has been called.
     *
     * @throws Throwable thrown if there is a problem
     */
    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize();
    }
    /**
     * Database properties object containing the 'properties' from the database
     * table.
     */
    private DatabaseProperties databaseProperties;

    /**
     * Get the value of databaseProperties.
     *
     * @return the value of databaseProperties
     */
    public DatabaseProperties getDatabaseProperties() {
        return databaseProperties;
    }
    //<editor-fold defaultstate="collapsed" desc="Constants to create, maintain, and retrieve data from the CVE Database">
    /**
     * SQL Statement to delete references by vulnerability ID.
     */
    private static final String DELETE_REFERENCE = "DELETE FROM reference WHERE cveid = ?";
    /**
     * SQL Statement to delete software by vulnerability ID.
     */
    private static final String DELETE_SOFTWARE = "DELETE FROM software WHERE cveid = ?";
    /**
     * SQL Statement to delete a vulnerability by CVE.
     */
    private static final String DELETE_VULNERABILITY = "DELETE FROM vulnerability WHERE id = ?";
    /**
     * SQL Statement to cleanup orphan entries. Yes, the db schema could be a
     * little tighter, but what we have works well to keep the data file size
     * down a bit.
     */
    private static final String CLEANUP_ORPHANS = "DELETE FROM CpeEntry WHERE id not in (SELECT CPEEntryId FROM Software); ";
    /**
     * SQL Statement to insert a new reference.
     */
    private static final String INSERT_REFERENCE = "INSERT INTO reference (cveid, name, url, source) VALUES (?, ?, ?, ?)";
    /**
     * SQL Statement to insert a new software.
     */
    private static final String INSERT_SOFTWARE = "INSERT INTO software (cveid, cpeEntryId, previousVersion) VALUES (?, ?, ?)";
    /**
     * SQL Statement to insert a new cpe.
     */
    private static final String INSERT_CPE = "INSERT INTO cpeEntry (cpe, vendor, product) VALUES (?, ?, ?)";
    /**
     * SQL Statement to get a CPEProductID.
     */
    private static final String SELECT_CPE_ID = "SELECT id FROM cpeEntry WHERE cpe = ?";
    /**
     * SQL Statement to insert a new vulnerability.
     */
    private static final String INSERT_VULNERABILITY = "INSERT INTO vulnerability (cve, description, cwe, cvssScore, cvssAccessVector, "
            + "cvssAccessComplexity, cvssAuthentication, cvssConfidentialityImpact, cvssIntegrityImpact, cvssAvailabilityImpact) "
            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    /**
     * SQL Statement to update a vulnerability.
     */
    private static final String UPDATE_VULNERABILITY = "UPDATE vulnerability SET description=?, cwe=?, cvssScore=?, cvssAccessVector=?, "
            + "cvssAccessComplexity=?, cvssAuthentication=?, cvssConfidentialityImpact=?, cvssIntegrityImpact=?, cvssAvailabilityImpact=? "
            + "WHERE id=?";
    /**
     * SQL Statement to find CVE entries based on CPE data.
     */
    private static final String SELECT_CVE_FROM_SOFTWARE = "SELECT cve, cpe, previousVersion "
            + "FROM software INNER JOIN vulnerability ON vulnerability.id = software.cveId "
            + "INNER JOIN cpeEntry ON cpeEntry.id = software.cpeEntryId "
            + "WHERE vendor = ? AND product = ?";
    //unfortunately, the version info is too complicated to do in a select. Need to filter this afterwards
    //        + " AND (version = '-' OR previousVersion IS NOT NULL OR version=?)";
    //
    /**
     * SQL Statement to find the CPE entry based on the vendor and product.
     */
    private static final String SELECT_CPE_ENTRIES = "SELECT cpe FROM cpeEntry WHERE vendor = ? AND product = ?";
    /**
     * SQL Statement to select references by CVEID.
     */
    private static final String SELECT_REFERENCE = "SELECT source, name, url FROM reference WHERE cveid = ?";
    /**
     * SQL Statement to select vendor and product for lucene index.
     */
    private static final String SELECT_VENDOR_PRODUCT_LIST = "SELECT vendor, product FROM cpeEntry GROUP BY vendor, product";
    /**
     * SQL Statement to select software by CVEID.
     */
    private static final String SELECT_SOFTWARE = "SELECT cpe, previousVersion "
            + "FROM software INNER JOIN cpeEntry ON software.cpeEntryId = cpeEntry.id WHERE cveid = ?";
//    public static final String SELECT_SOFTWARE = "SELECT part, vendor, product, version, revision, previousVersion "
//            + "FROM software INNER JOIN cpeProduct ON cpeProduct.id = software.cpeProductId LEFT JOIN cpeVersion ON "
//            + "software.cpeVersionId = cpeVersion.id LEFT JOIN Version ON cpeVersion.versionId = version.id WHERE cveid = ?";
    /**
     * SQL Statement to select a vulnerability by CVEID.
     */
    private static final String SELECT_VULNERABILITY = "SELECT id, description, cwe, cvssScore, cvssAccessVector, cvssAccessComplexity, "
            + "cvssAuthentication, cvssConfidentialityImpact, cvssIntegrityImpact, cvssAvailabilityImpact FROM vulnerability WHERE cve = ?";
    /**
     * SQL Statement to select a vulnerability's primary key.
     */
    private static final String SELECT_VULNERABILITY_ID = "SELECT id FROM vulnerability WHERE cve = ?";
    /**
     * SQL Statement to retrieve the properties from the database.
     */
    private static final String SELECT_PROPERTIES = "SELECT id, value FROM properties";
    /**
     * SQL Statement to retrieve a property from the database.
     */
    private static final String SELECT_PROPERTY = "SELECT id, value FROM properties WHERE id = ?";
    /**
     * SQL Statement to insert a new property.
     */
    private static final String INSERT_PROPERTY = "INSERT INTO properties (id, value) VALUES (?, ?)";
    /**
     * SQL Statement to update a property.
     */
    private static final String UPDATE_PROPERTY = "UPDATE properties SET value = ? WHERE id = ?";
    /**
     * SQL Statement to delete a property.
     */
    private static final String DELETE_PROPERTY = "DELETE FROM properties WHERE id = ?";

    //</editor-fold>
    /**
     * Searches the CPE entries in the database and retrieves all entries for a
     * given vendor and product combination. The returned list will include all
     * versions of the product that are registered in the NVD CVE data.
     *
     * @param vendor the identified vendor name of the dependency being analyzed
     * @param product the identified name of the product of the dependency being
     * analyzed
     * @return a set of vulnerable software
     */
    public Set<VulnerableSoftware> getCPEs(String vendor, String product) {
        final Set<VulnerableSoftware> cpe = new HashSet<VulnerableSoftware>();
        ResultSet rs = null;
        PreparedStatement ps = null;
        try {
            ps = getConnection().prepareStatement(SELECT_CPE_ENTRIES);
            ps.setString(1, vendor);
            ps.setString(2, product);
            rs = ps.executeQuery();

            while (rs.next()) {
                final VulnerableSoftware vs = new VulnerableSoftware();
                vs.setCpe(rs.getString(1));
                cpe.add(vs);
            }
        } catch (SQLException ex) {
            final String msg = "An unexpected SQL Exception occurred; please see the verbose log for more details.";
            Logger.getLogger(CveDB.class.getName()).log(Level.SEVERE, msg);
            Logger.getLogger(CveDB.class.getName()).log(Level.FINE, null, ex);
        } finally {
            DBUtils.closeResultSet(rs);
            DBUtils.closeStatement(ps);
        }
        return cpe;
    }

    /**
     * Returns the entire list of vendor/product combinations.
     *
     * @return the entire list of vendor/product combinations.
     */
    public ResultSet getVendorProductList() {
        ResultSet rs = null;
        try {
            final PreparedStatement ps = getConnection().prepareStatement(SELECT_VENDOR_PRODUCT_LIST);
            rs = ps.executeQuery();
        } catch (SQLException ex) {
            final String msg = "An unexpected SQL Exception occurred; please see the verbose log for more details.";
            Logger.getLogger(CveDB.class.getName()).log(Level.SEVERE, msg);
            Logger.getLogger(CveDB.class.getName()).log(Level.FINE, null, ex);
        } // can't close the statement in the PS as the resultset is returned, closing PS would close the resultset
        return rs;
    }

    /**
     * Returns a set of properties.
     *
     * @return the properties from the database
     */
    Properties getProperties() {
        final Properties prop = new Properties();
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            ps = getConnection().prepareStatement(SELECT_PROPERTIES);
            rs = ps.executeQuery();
            while (rs.next()) {
                prop.setProperty(rs.getString(1), rs.getString(2));
            }
        } catch (SQLException ex) {
            final String msg = "An unexpected SQL Exception occurred; please see the verbose log for more details.";
            Logger.getLogger(CveDB.class.getName()).log(Level.SEVERE, msg);
            Logger.getLogger(CveDB.class.getName()).log(Level.FINE, null, ex);
        } finally {
            DBUtils.closeStatement(ps);
            DBUtils.closeResultSet(rs);
        }
        return prop;
    }

    /**
     * Saves a set of properties to the database.
     *
     * @param props a collection of properties
     */
    void saveProperties(Properties props) {
        PreparedStatement updateProperty = null;
        PreparedStatement insertProperty = null;
        try {
            try {
                updateProperty = getConnection().prepareStatement(UPDATE_PROPERTY);
                insertProperty = getConnection().prepareStatement(INSERT_PROPERTY);
            } catch (SQLException ex) {
                Logger.getLogger(CveDB.class.getName()).log(Level.WARNING, "Unable to save properties to the database");
                Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Unable to save properties to the database", ex);
                return;
            }
            for (Entry<Object, Object> entry : props.entrySet()) {
                final String key = entry.getKey().toString();
                final String value = entry.getValue().toString();
                try {
                    updateProperty.setString(1, value);
                    updateProperty.setString(2, key);
                    if (updateProperty.executeUpdate() == 0) {
                        insertProperty.setString(1, key);
                        insertProperty.setString(2, value);
                    }
                } catch (SQLException ex) {
                    final String msg = String.format("Unable to save property '%s' with a value of '%s' to the database", key, value);
                    Logger.getLogger(CveDB.class.getName()).log(Level.WARNING, msg);
                    Logger.getLogger(CveDB.class.getName()).log(Level.FINE, null, ex);
                }
            }
        } finally {
            DBUtils.closeStatement(updateProperty);
            DBUtils.closeStatement(insertProperty);
        }
    }

    /**
     * Saves a property to the database.
     *
     * @param key the property key
     * @param value the property value
     */
    void saveProperty(String key, String value) {
        PreparedStatement updateProperty = null;
        PreparedStatement insertProperty = null;
        try {
            try {
                updateProperty = getConnection().prepareStatement(UPDATE_PROPERTY);
            } catch (SQLException ex) {
                Logger.getLogger(CveDB.class.getName()).log(Level.WARNING, "Unable to save properties to the database");
                Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Unable to save properties to the database", ex);
                return;
            }
            try {
                updateProperty.setString(1, value);
                updateProperty.setString(2, key);
                if (updateProperty.executeUpdate() == 0) {
                    try {
                        insertProperty = getConnection().prepareStatement(INSERT_PROPERTY);
                    } catch (SQLException ex) {
                        Logger.getLogger(CveDB.class.getName()).log(Level.WARNING, "Unable to save properties to the database");
                        Logger.getLogger(CveDB.class.getName()).log(Level.FINE, "Unable to save properties to the database", ex);
                        return;
                    }
                    insertProperty.setString(1, key);
                    insertProperty.setString(2, value);
                    insertProperty.execute();
                }
            } catch (SQLException ex) {
                final String msg = String.format("Unable to save property '%s' with a value of '%s' to the database", key, value);
                Logger.getLogger(CveDB.class.getName()).log(Level.WARNING, msg);
                Logger.getLogger(CveDB.class.getName()).log(Level.FINE, null, ex);
            }
        } finally {
            DBUtils.closeStatement(updateProperty);
            DBUtils.closeStatement(insertProperty);
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
        final VulnerableSoftware cpe = new VulnerableSoftware();
        try {
            cpe.parseName(cpeStr);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(CveDB.class.getName()).log(Level.FINEST, null, ex);
        }
        final DependencyVersion detectedVersion = parseDependencyVersion(cpe);
        final List<Vulnerability> vulnerabilities = new ArrayList<Vulnerability>();

        PreparedStatement ps;
        final HashSet<String> cveEntries = new HashSet<String>();
        try {
            ps = getConnection().prepareStatement(SELECT_CVE_FROM_SOFTWARE);
            ps.setString(1, cpe.getVendor());
            ps.setString(2, cpe.getProduct());
            rs = ps.executeQuery();
            while (rs.next()) {
                final String cveId = rs.getString(1);
                final String cpeId = rs.getString(2);
                final String previous = rs.getString(3);
                if (!cveEntries.contains(cveId) && isAffected(cpe.getVendor(), cpe.getProduct(), detectedVersion, cpeId, previous)) {
                    cveEntries.add(cveId);
                }
            }
            DBUtils.closeResultSet(rs);
            DBUtils.closeStatement(ps);
            for (String cve : cveEntries) {
                final Vulnerability v = getVulnerability(cve);
                vulnerabilities.add(v);
            }

        } catch (SQLException ex) {
            throw new DatabaseException("Exception retrieving vulnerability for " + cpeStr, ex);
        } finally {
            DBUtils.closeResultSet(rs);
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
        PreparedStatement psV = null;
        PreparedStatement psR = null;
        PreparedStatement psS = null;
        ResultSet rsV = null;
        ResultSet rsR = null;
        ResultSet rsS = null;
        Vulnerability vuln = null;
        try {
            psV = getConnection().prepareStatement(SELECT_VULNERABILITY);
            psV.setString(1, cve);
            rsV = psV.executeQuery();
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
                final int cveId = rsV.getInt(1);
                vuln.setCwe(cwe);
                vuln.setCvssScore(rsV.getFloat(4));
                vuln.setCvssAccessVector(rsV.getString(5));
                vuln.setCvssAccessComplexity(rsV.getString(6));
                vuln.setCvssAuthentication(rsV.getString(7));
                vuln.setCvssConfidentialityImpact(rsV.getString(8));
                vuln.setCvssIntegrityImpact(rsV.getString(9));
                vuln.setCvssAvailabilityImpact(rsV.getString(10));

                psR = getConnection().prepareStatement(SELECT_REFERENCE);
                psR.setInt(1, cveId);
                rsR = psR.executeQuery();
                while (rsR.next()) {
                    vuln.addReference(rsR.getString(1), rsR.getString(2), rsR.getString(3));
                }
                psS = getConnection().prepareStatement(SELECT_SOFTWARE);
                psS.setInt(1, cveId);
                rsS = psS.executeQuery();
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
            DBUtils.closeResultSet(rsV);
            DBUtils.closeResultSet(rsR);
            DBUtils.closeResultSet(rsS);
            DBUtils.closeStatement(psV);
            DBUtils.closeStatement(psR);
            DBUtils.closeStatement(psS);
        }
        return vuln;
    }

    /**
     * Updates the vulnerability within the database. If the vulnerability does
     * not exist it will be added.
     *
     * @param vuln the vulnerability to add to the database
     * @throws DatabaseException is thrown if the database
     */
    public void updateVulnerability(Vulnerability vuln) throws DatabaseException {
        PreparedStatement selectVulnerabilityId = null;
        PreparedStatement deleteVulnerability = null;
        PreparedStatement deleteReferences = null;
        PreparedStatement deleteSoftware = null;
        PreparedStatement updateVulnerability = null;
        PreparedStatement insertVulnerability = null;
        PreparedStatement insertReference = null;
        PreparedStatement selectCpeId = null;
        PreparedStatement insertCpe = null;
        PreparedStatement insertSoftware = null;

        try {
            selectVulnerabilityId = getConnection().prepareStatement(SELECT_VULNERABILITY_ID);
            deleteVulnerability = getConnection().prepareStatement(DELETE_VULNERABILITY);
            deleteReferences = getConnection().prepareStatement(DELETE_REFERENCE);
            deleteSoftware = getConnection().prepareStatement(DELETE_SOFTWARE);
            updateVulnerability = getConnection().prepareStatement(UPDATE_VULNERABILITY);
            insertVulnerability = getConnection().prepareStatement(INSERT_VULNERABILITY, Statement.RETURN_GENERATED_KEYS);
            insertReference = getConnection().prepareStatement(INSERT_REFERENCE);
            selectCpeId = getConnection().prepareStatement(SELECT_CPE_ID);
            insertCpe = getConnection().prepareStatement(INSERT_CPE, Statement.RETURN_GENERATED_KEYS);
            insertSoftware = getConnection().prepareStatement(INSERT_SOFTWARE);
            int vulnerabilityId = 0;
            selectVulnerabilityId.setString(1, vuln.getName());
            ResultSet rs = selectVulnerabilityId.executeQuery();
            if (rs.next()) {
                vulnerabilityId = rs.getInt(1);
                // first delete any existing vulnerability info. We don't know what was updated. yes, slower but atm easier.
                deleteReferences.setInt(1, vulnerabilityId);
                deleteReferences.execute();
                deleteSoftware.setInt(1, vulnerabilityId);
                deleteSoftware.execute();
            }
            DBUtils.closeResultSet(rs);
            rs = null;
            if (vulnerabilityId != 0) {
                if (vuln.getDescription().contains("** REJECT **")) {
                    deleteVulnerability.setInt(1, vulnerabilityId);
                    deleteVulnerability.executeUpdate();
                } else {
                    updateVulnerability.setString(1, vuln.getDescription());
                    updateVulnerability.setString(2, vuln.getCwe());
                    updateVulnerability.setFloat(3, vuln.getCvssScore());
                    updateVulnerability.setString(4, vuln.getCvssAccessVector());
                    updateVulnerability.setString(5, vuln.getCvssAccessComplexity());
                    updateVulnerability.setString(6, vuln.getCvssAuthentication());
                    updateVulnerability.setString(7, vuln.getCvssConfidentialityImpact());
                    updateVulnerability.setString(8, vuln.getCvssIntegrityImpact());
                    updateVulnerability.setString(9, vuln.getCvssAvailabilityImpact());
                    updateVulnerability.setInt(10, vulnerabilityId);
                    updateVulnerability.executeUpdate();
                }
            } else {
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
                try {
                    rs = insertVulnerability.getGeneratedKeys();
                    rs.next();
                    vulnerabilityId = rs.getInt(1);
                } catch (SQLException ex) {
                    final String msg = String.format("Unable to retrieve id for new vulnerability for '%s'", vuln.getName());
                    throw new DatabaseException(msg, ex);
                } finally {
                    DBUtils.closeResultSet(rs);
                    rs = null;
                }
            }
            insertReference.setInt(1, vulnerabilityId);
            for (Reference r : vuln.getReferences()) {
                insertReference.setString(2, r.getName());
                insertReference.setString(3, r.getUrl());
                insertReference.setString(4, r.getSource());
                insertReference.execute();
            }
            for (VulnerableSoftware s : vuln.getVulnerableSoftware()) {
                int cpeProductId = 0;
                selectCpeId.setString(1, s.getName());
                try {
                    rs = selectCpeId.executeQuery();
                    if (rs.next()) {
                        cpeProductId = rs.getInt(1);
                    }
                } catch (SQLException ex) {
                    throw new DatabaseException("Unable to get primary key for new cpe: " + s.getName(), ex);
                } finally {
                    DBUtils.closeResultSet(rs);
                    rs = null;
                }

                if (cpeProductId == 0) {
                    insertCpe.setString(1, s.getName());
                    insertCpe.setString(2, s.getVendor());
                    insertCpe.setString(3, s.getProduct());
                    insertCpe.executeUpdate();
                    cpeProductId = DBUtils.getGeneratedKey(insertCpe);
                }
                if (cpeProductId == 0) {
                    throw new DatabaseException("Unable to retrieve cpeProductId - no data returned");
                }

                insertSoftware.setInt(1, vulnerabilityId);
                insertSoftware.setInt(2, cpeProductId);
                if (s.getPreviousVersion() == null) {
                    insertSoftware.setNull(3, java.sql.Types.VARCHAR);
                } else {
                    insertSoftware.setString(3, s.getPreviousVersion());
                }
                insertSoftware.execute();
            }

        } catch (SQLException ex) {
            final String msg = String.format("Error updating '%s'", vuln.getName());
            Logger.getLogger(CveDB.class.getName()).log(Level.FINE, null, ex);
            throw new DatabaseException(msg, ex);
        } finally {
            DBUtils.closeStatement(selectVulnerabilityId);
            DBUtils.closeStatement(deleteReferences);
            DBUtils.closeStatement(deleteSoftware);
            DBUtils.closeStatement(updateVulnerability);
            DBUtils.closeStatement(deleteVulnerability);
            DBUtils.closeStatement(insertVulnerability);
            DBUtils.closeStatement(insertReference);
            DBUtils.closeStatement(selectCpeId);
            DBUtils.closeStatement(insertCpe);
            DBUtils.closeStatement(insertSoftware);
        }
    }

    /**
     * It is possible that orphaned rows may be generated during database
     * updates. This should be called after all updates have been completed to
     * ensure orphan entries are removed.
     */
    public void cleanupDatabase() {
        PreparedStatement ps = null;
        try {
            ps = getConnection().prepareStatement(CLEANUP_ORPHANS);
            if (ps != null) {
                ps.executeUpdate();
            }
        } catch (SQLException ex) {
            final String msg = "An unexpected SQL Exception occurred; please see the verbose log for more details.";
            Logger.getLogger(CveDB.class.getName()).log(Level.SEVERE, msg);
            Logger.getLogger(CveDB.class.getName()).log(Level.FINE, null, ex);
        } finally {
            DBUtils.closeStatement(ps);
        }
    }

    /**
     * Determines if the given identifiedVersion is affected by the given cpeId
     * and previous version flag. A non-null, non-empty string passed to the
     * previous version argument indicates that all previous versions are
     * affected.
     *
     * @param vendor the vendor of the dependency being analyzed
     * @param product the product name of the dependency being analyzed
     * @param identifiedVersion the identified version of the dependency being
     * analyzed
     * @param cpeId the cpe identifier of software that has a known
     * vulnerability
     * @param previous a flag indicating if previous versions of the product are
     * vulnerable
     * @return true if the identified version is affected, otherwise false
     */
    private boolean isAffected(String vendor, String product, DependencyVersion identifiedVersion, String cpeId, String previous) {
        boolean affected = false;
        final boolean isStruts = "apache".equals(vendor) && "struts".equals(product);
        final DependencyVersion v = parseDependencyVersion(cpeId);
        final boolean prevAffected = previous != null && !previous.isEmpty();
        if (identifiedVersion == null || "-".equals(identifiedVersion.toString())) {
            if (v == null || "-".equals(v.toString())) {
                affected = true;
            }
        } else if (identifiedVersion.equals(v) || (prevAffected && identifiedVersion.compareTo(v) < 0)) {
            if (isStruts) { //struts 2 vulns don't affect struts 1
                if (identifiedVersion.getVersionParts().get(0).equals(v.getVersionParts().get(0))) {
                    affected = true;
                }
            } else {
                affected = true;
            }
        }
        /*
         * TODO consider utilizing the matchThreeVersion method to get additional results. However, this
         *      might also introduce false positives.
         */
        return affected;
    }

    /**
     * Parses the version (including revision) from a CPE identifier. If no
     * version is identified then a '-' is returned.
     *
     * @param cpeStr a cpe identifier
     * @return a dependency version
     */
    private DependencyVersion parseDependencyVersion(String cpeStr) {
        final VulnerableSoftware cpe = new VulnerableSoftware();
        try {
            cpe.parseName(cpeStr);
        } catch (UnsupportedEncodingException ex) {
            //never going to happen.
            Logger.getLogger(CveDB.class.getName()).log(Level.FINEST, null, ex);
        }
        return parseDependencyVersion(cpe);
    }

    /**
     * Takes a CPE and parses out the version number. If no version is
     * identified then a '-' is returned.
     *
     * @param cpe a cpe object
     * @return a dependency version
     */
    private DependencyVersion parseDependencyVersion(VulnerableSoftware cpe) {
        DependencyVersion cpeVersion;
        if (cpe.getVersion() != null && cpe.getVersion().length() > 0) {
            String versionText;
            if (cpe.getRevision() != null && cpe.getRevision().length() > 0) {
                versionText = String.format("%s.%s", cpe.getVersion(), cpe.getRevision());
            } else {
                versionText = cpe.getVersion();
            }
            cpeVersion = DependencyVersionUtil.parseVersion(versionText);
        } else {
            cpeVersion = new DependencyVersion("-");
        }
        return cpeVersion;
    }
}
