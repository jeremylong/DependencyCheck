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
package org.owasp.dependencycheck.data.nvdcve;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.owasp.dependencycheck.data.cwe.CweDB;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.DBUtils;
import org.owasp.dependencycheck.utils.DependencyVersion;
import org.owasp.dependencycheck.utils.DependencyVersionUtil;
import org.owasp.dependencycheck.utils.Pair;
import org.owasp.dependencycheck.utils.Settings;

/**
 * The database holding information about the NVD CVE data.
 *
 * @author Jeremy Long
 */
public class CveDB {

    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(CveDB.class.getName());
    /**
     * Database connection
     */
    private Connection conn;
    /**
     * The bundle of statements used when accessing the database.
     */
    private ResourceBundle statementBundle = null;

    /**
     * Creates a new CveDB object and opens the database connection. Note, the connection must be closed by the caller by calling
     * the close method.
     *
     * @throws DatabaseException thrown if there is an exception opening the database.
     */
    public CveDB() throws DatabaseException {
        super();
        statementBundle = java.util.ResourceBundle.getBundle("data/dbStatements");
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
     * Opens the database connection. If the database does not exist, it will create a new one.
     *
     * @throws DatabaseException thrown if there is an error opening the database connection
     */
    public final void open() throws DatabaseException {
        if (!isOpen()) {
            conn = ConnectionFactory.getConnection();
        }
    }

    /**
     * Closes the DB4O database. Close should be called on this object when it is done being used.
     */
    public void close() {
        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException ex) {
                final String msg = "There was an error attempting to close the CveDB, see the log for more details.";
                LOGGER.log(Level.SEVERE, msg);
                LOGGER.log(Level.FINE, null, ex);
            } catch (Throwable ex) {
                final String msg = "There was an exception attempting to close the CveDB, see the log for more details.";
                LOGGER.log(Level.SEVERE, msg);
                LOGGER.log(Level.FINE, null, ex);
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
        //temporary remove this as autocommit is on.
        //if (conn != null) {
        //    conn.commit();
        //}
    }

    /**
     * Cleans up the object and ensures that "close" has been called.
     *
     * @throws Throwable thrown if there is a problem
     */
    @Override
    @SuppressWarnings("FinalizeDeclaration")
    protected void finalize() throws Throwable {
        LOGGER.log(Level.FINE, "Entering finalize");
        close();
        super.finalize();
    }
    /**
     * Database properties object containing the 'properties' from the database table.
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

    /**
     * Searches the CPE entries in the database and retrieves all entries for a given vendor and product combination. The returned
     * list will include all versions of the product that are registered in the NVD CVE data.
     *
     * @param vendor the identified vendor name of the dependency being analyzed
     * @param product the identified name of the product of the dependency being analyzed
     * @return a set of vulnerable software
     */
    public Set<VulnerableSoftware> getCPEs(String vendor, String product) {
        final Set<VulnerableSoftware> cpe = new HashSet<VulnerableSoftware>();
        ResultSet rs = null;
        PreparedStatement ps = null;
        try {
            ps = getConnection().prepareStatement(statementBundle.getString("SELECT_CPE_ENTRIES"));
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
            LOGGER.log(Level.SEVERE, msg);
            LOGGER.log(Level.FINE, null, ex);
        } finally {
            DBUtils.closeResultSet(rs);
            DBUtils.closeStatement(ps);
        }
        return cpe;
    }

    /**
     * Returns the entire list of vendor/product combinations.
     *
     * @return the entire list of vendor/product combinations
     * @throws DatabaseException thrown when there is an error retrieving the data from the DB
     */
    public Set<Pair<String, String>> getVendorProductList() throws DatabaseException {
        final Set<Pair<String, String>> data = new HashSet<Pair<String, String>>();
        ResultSet rs = null;
        PreparedStatement ps = null;
        try {
            ps = getConnection().prepareStatement(statementBundle.getString("SELECT_VENDOR_PRODUCT_LIST"));
            rs = ps.executeQuery();
            while (rs.next()) {
                data.add(new Pair<String, String>(rs.getString(1), rs.getString(2)));
            }
        } catch (SQLException ex) {
            final String msg = "An unexpected SQL Exception occurred; please see the verbose log for more details.";
            throw new DatabaseException(msg, ex);
        } finally {
            DBUtils.closeResultSet(rs);
            DBUtils.closeStatement(ps);
        }
        return data;
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
            ps = getConnection().prepareStatement(statementBundle.getString("SELECT_PROPERTIES"));
            rs = ps.executeQuery();
            while (rs.next()) {
                prop.setProperty(rs.getString(1), rs.getString(2));
            }
        } catch (SQLException ex) {
            final String msg = "An unexpected SQL Exception occurred; please see the verbose log for more details.";
            LOGGER.log(Level.SEVERE, msg);
            LOGGER.log(Level.FINE, null, ex);
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
                updateProperty = getConnection().prepareStatement(statementBundle.getString("UPDATE_PROPERTY"));
                insertProperty = getConnection().prepareStatement(statementBundle.getString("INSERT_PROPERTY"));
            } catch (SQLException ex) {
                LOGGER.log(Level.WARNING, "Unable to save properties to the database");
                LOGGER.log(Level.FINE, "Unable to save properties to the database", ex);
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
                    LOGGER.log(Level.WARNING, msg);
                    LOGGER.log(Level.FINE, null, ex);
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
                updateProperty = getConnection().prepareStatement(statementBundle.getString("UPDATE_PROPERTY"));
            } catch (SQLException ex) {
                LOGGER.log(Level.WARNING, "Unable to save properties to the database");
                LOGGER.log(Level.FINE, "Unable to save properties to the database", ex);
                return;
            }
            try {
                updateProperty.setString(1, value);
                updateProperty.setString(2, key);
                if (updateProperty.executeUpdate() == 0) {
                    try {
                        insertProperty = getConnection().prepareStatement(statementBundle.getString("INSERT_PROPERTY"));
                    } catch (SQLException ex) {
                        LOGGER.log(Level.WARNING, "Unable to save properties to the database");
                        LOGGER.log(Level.FINE, "Unable to save properties to the database", ex);
                        return;
                    }
                    insertProperty.setString(1, key);
                    insertProperty.setString(2, value);
                    insertProperty.execute();
                }
            } catch (SQLException ex) {
                final String msg = String.format("Unable to save property '%s' with a value of '%s' to the database", key, value);
                LOGGER.log(Level.WARNING, msg);
                LOGGER.log(Level.FINE, null, ex);
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
            LOGGER.log(Level.FINEST, null, ex);
        }
        final DependencyVersion detectedVersion = parseDependencyVersion(cpe);
        final List<Vulnerability> vulnerabilities = new ArrayList<Vulnerability>();

        PreparedStatement ps;
        try {
            ps = getConnection().prepareStatement(statementBundle.getString("SELECT_CVE_FROM_SOFTWARE"));
            ps.setString(1, cpe.getVendor());
            ps.setString(2, cpe.getProduct());
            rs = ps.executeQuery();
            String currentCVE = "";

            final Map<String, Boolean> vulnSoftware = new HashMap<String, Boolean>();
            while (rs.next()) {
                final String cveId = rs.getString(1);
                if (!currentCVE.equals(cveId)) { //check for match and add
                    final Entry<String, Boolean> matchedCPE = getMatchingSoftware(vulnSoftware, cpe.getVendor(), cpe.getProduct(), detectedVersion);
                    if (matchedCPE != null) {
                        final Vulnerability v = getVulnerability(currentCVE);
                        v.setMatchedCPE(matchedCPE.getKey(), matchedCPE.getValue() ? "Y" : null);
                        vulnerabilities.add(v);
                    }
                    vulnSoftware.clear();
                    currentCVE = cveId;
                }

                final String cpeId = rs.getString(2);
                final String previous = rs.getString(3);
                final Boolean p = previous != null && !previous.isEmpty();
                vulnSoftware.put(cpeId, p);
            }
            //remember to process the last set of CVE/CPE entries
            final Entry<String, Boolean> matchedCPE = getMatchingSoftware(vulnSoftware, cpe.getVendor(), cpe.getProduct(), detectedVersion);
            if (matchedCPE != null) {
                final Vulnerability v = getVulnerability(currentCVE);
                v.setMatchedCPE(matchedCPE.getKey(), matchedCPE.getValue() ? "Y" : null);
                vulnerabilities.add(v);
            }
            DBUtils.closeResultSet(rs);
            DBUtils.closeStatement(ps);
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
            psV = getConnection().prepareStatement(statementBundle.getString("SELECT_VULNERABILITY"));
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

                psR = getConnection().prepareStatement(statementBundle.getString("SELECT_REFERENCES"));
                psR.setInt(1, cveId);
                rsR = psR.executeQuery();
                while (rsR.next()) {
                    vuln.addReference(rsR.getString(1), rsR.getString(2), rsR.getString(3));
                }
                psS = getConnection().prepareStatement(statementBundle.getString("SELECT_SOFTWARE"));
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
     * Updates the vulnerability within the database. If the vulnerability does not exist it will be added.
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
            selectVulnerabilityId = getConnection().prepareStatement(statementBundle.getString("SELECT_VULNERABILITY_ID"));
            deleteVulnerability = getConnection().prepareStatement(statementBundle.getString("DELETE_VULNERABILITY"));
            deleteReferences = getConnection().prepareStatement(statementBundle.getString("DELETE_REFERENCE"));
            deleteSoftware = getConnection().prepareStatement(statementBundle.getString("DELETE_SOFTWARE"));
            updateVulnerability = getConnection().prepareStatement(statementBundle.getString("UPDATE_VULNERABILITY"));
            insertVulnerability = getConnection().prepareStatement(statementBundle.getString("INSERT_VULNERABILITY"),
                    Statement.RETURN_GENERATED_KEYS);
            insertReference = getConnection().prepareStatement(statementBundle.getString("INSERT_REFERENCE"));
            selectCpeId = getConnection().prepareStatement(statementBundle.getString("SELECT_CPE_ID"));
            insertCpe = getConnection().prepareStatement(statementBundle.getString("INSERT_CPE"),
                    Statement.RETURN_GENERATED_KEYS);
            insertSoftware = getConnection().prepareStatement(statementBundle.getString("INSERT_SOFTWARE"));
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
            LOGGER.log(Level.FINE, null, ex);
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
     * Checks to see if data exists so that analysis can be performed.
     *
     * @return <code>true</code> if data exists; otherwise <code>false</code>
     */
    public boolean dataExists() {
        Statement cs = null;
        ResultSet rs = null;
        try {
            cs = conn.createStatement();
            rs = cs.executeQuery("SELECT COUNT(*) records FROM cpeEntry");
            if (rs.next()) {
                if (rs.getInt(1) > 0) {
                    return true;
                }
            }
        } catch (SQLException ex) {
            String dd;
            try {
                dd = Settings.getDataDirectory().getAbsolutePath();
            } catch (IOException ex1) {
                dd = Settings.getString(Settings.KEYS.DATA_DIRECTORY);
            }
            final String msg = String.format("Unable to access the local database.%n%nEnsure that '%s' is a writable directory. "
                    + "If the problem persist try deleting the files in '%s' and running %s again. If the problem continues, please "
                    + "create a log file (see documentation at http://jeremylong.github.io/DependencyCheck/) and open a ticket at "
                    + "https://github.com/jeremylong/DependencyCheck/issues and include the log file.%n%n",
                    dd, dd, Settings.getString(Settings.KEYS.APPLICATION_VAME));
            LOGGER.log(Level.SEVERE, msg);
            LOGGER.log(Level.FINE, "", ex);
        } finally {
            DBUtils.closeResultSet(rs);
            DBUtils.closeStatement(cs);
        }
        return false;
    }

    /**
     * It is possible that orphaned rows may be generated during database updates. This should be called after all updates have
     * been completed to ensure orphan entries are removed.
     */
    public void cleanupDatabase() {
        PreparedStatement ps = null;
        try {
            ps = getConnection().prepareStatement(statementBundle.getString("CLEANUP_ORPHANS"));
            if (ps != null) {
                ps.executeUpdate();
            }
        } catch (SQLException ex) {
            final String msg = "An unexpected SQL Exception occurred; please see the verbose log for more details.";
            LOGGER.log(Level.SEVERE, msg);
            LOGGER.log(Level.FINE, null, ex);
        } finally {
            DBUtils.closeStatement(ps);
        }
    }

    /**
     * Determines if the given identifiedVersion is affected by the given cpeId and previous version flag. A non-null, non-empty
     * string passed to the previous version argument indicates that all previous versions are affected.
     *
     * @param vendor the vendor of the dependency being analyzed
     * @param product the product name of the dependency being analyzed
     * @param vulnerableSoftware a map of the vulnerable software with a boolean indicating if all previous versions are affected
     * @param identifiedVersion the identified version of the dependency being analyzed
     * @return true if the identified version is affected, otherwise false
     */
    Entry<String, Boolean> getMatchingSoftware(Map<String, Boolean> vulnerableSoftware, String vendor, String product,
            DependencyVersion identifiedVersion) {

        final boolean isVersionTwoADifferentProduct = "apache".equals(vendor) && "struts".equals(product);

        final Set<String> majorVersionsAffectingAllPrevious = new HashSet<String>();
        final boolean matchesAnyPrevious = identifiedVersion == null || "-".equals(identifiedVersion.toString());
        String majorVersionMatch = null;
        for (Entry<String, Boolean> entry : vulnerableSoftware.entrySet()) {
            final DependencyVersion v = parseDependencyVersion(entry.getKey());
            if (v == null || "-".equals(v.toString())) { //all versions
                return entry;
            }
            if (entry.getValue()) {
                if (matchesAnyPrevious) {
                    return entry;
                }
                if (identifiedVersion != null && identifiedVersion.getVersionParts().get(0).equals(v.getVersionParts().get(0))) {
                    majorVersionMatch = v.getVersionParts().get(0);
                }
                majorVersionsAffectingAllPrevious.add(v.getVersionParts().get(0));
            }
        }
        if (matchesAnyPrevious) {
            return null;
        }

        final boolean canSkipVersions = majorVersionMatch != null && majorVersionsAffectingAllPrevious.size() > 1;
        //yes, we are iterating over this twice. The first time we are skipping versions those that affect all versions
        //then later we process those that affect all versions. This could be done with sorting...
        for (Entry<String, Boolean> entry : vulnerableSoftware.entrySet()) {
            if (!entry.getValue()) {
                final DependencyVersion v = parseDependencyVersion(entry.getKey());
                //this can't dereference a null 'majorVersionMatch' as canSkipVersions accounts for this.
                if (canSkipVersions && !majorVersionMatch.equals(v.getVersionParts().get(0))) {
                    continue;
                }
                //this can't dereference a null 'identifiedVersion' because if it was null we would have exited
                //in the above loop or just after loop (if matchesAnyPrevious return null).
                if (identifiedVersion.equals(v)) {
                    return entry;
                }
            }
        }
        for (Entry<String, Boolean> entry : vulnerableSoftware.entrySet()) {
            if (entry.getValue()) {
                final DependencyVersion v = parseDependencyVersion(entry.getKey());
                //this can't dereference a null 'majorVersionMatch' as canSkipVersions accounts for this.
                if (canSkipVersions && !majorVersionMatch.equals(v.getVersionParts().get(0))) {
                    continue;
                }
                //this can't dereference a null 'identifiedVersion' because if it was null we would have exited
                //in the above loop or just after loop (if matchesAnyPrevious return null).
                if (entry.getValue() && identifiedVersion.compareTo(v) <= 0) {
                    if (!(isVersionTwoADifferentProduct && !identifiedVersion.getVersionParts().get(0).equals(v.getVersionParts().get(0)))) {
                        return entry;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Parses the version (including revision) from a CPE identifier. If no version is identified then a '-' is returned.
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
            LOGGER.log(Level.FINEST, null, ex);
        }
        return parseDependencyVersion(cpe);
    }

    /**
     * Takes a CPE and parses out the version number. If no version is identified then a '-' is returned.
     *
     * @param cpe a cpe object
     * @return a dependency version
     */
    private DependencyVersion parseDependencyVersion(VulnerableSoftware cpe) {
        DependencyVersion cpeVersion;
        if (cpe.getVersion() != null && !cpe.getVersion().isEmpty()) {
            String versionText;
            if (cpe.getRevision() != null && !cpe.getRevision().isEmpty()) {
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
