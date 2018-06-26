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
//CSOFF: AvoidStarImport
import org.apache.commons.collections.map.ReferenceMap;
import org.owasp.dependencycheck.data.cwe.CweDB;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.Map.Entry;

import static org.apache.commons.collections.map.AbstractReferenceMap.HARD;
import static org.apache.commons.collections.map.AbstractReferenceMap.SOFT;
import static org.owasp.dependencycheck.data.nvdcve.CveDB.PreparedStatementCveDb.*;
//CSON: AvoidStarImport
/**
 * The database holding information about the NVD CVE data. This class is safe
 * to be accessed from multiple threads in parallel, however internally only one
 * connection will be used.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public final class CveDB implements AutoCloseable {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CveDB.class);

    /**
     * The database connection factory.
     */
    private final ConnectionFactory connectionFactory;
    /**
     * Database connection
     */
    private Connection connection;
    /**
     * The bundle of statements used when accessing the database.
     */
    private ResourceBundle statementBundle;
    /**
     * Database properties object containing the 'properties' from the database
     * table.
     */
    private DatabaseProperties databaseProperties;
    /**
     * The prepared statements.
     */
    private final EnumMap<PreparedStatementCveDb, PreparedStatement> preparedStatements = new EnumMap<>(PreparedStatementCveDb.class);

    /**
     * Cache for CVE lookups; used to speed up the vulnerability search process.
     */
    @SuppressWarnings("unchecked")
    private final Map<String, List<Vulnerability>> vulnerabilitiesForCpeCache = Collections.synchronizedMap(new ReferenceMap(HARD, SOFT));
    /**
     * The configured settings
     */
    private final Settings settings;

    /**
     * The enum value names must match the keys of the statements in the
     * statement bundles "dbStatements*.properties".
     */
    enum PreparedStatementCveDb {
        /**
         * Key for SQL Statement.
         */
        CLEANUP_ORPHANS,
        /**
         * Key for SQL Statement.
         */
        COUNT_CPE,
        /**
         * Key for SQL Statement.
         */
        DELETE_REFERENCE,
        /**
         * Key for SQL Statement.
         */
        DELETE_SOFTWARE,
        /**
         * Key for SQL Statement.
         */
        DELETE_VULNERABILITY,
        /**
         * Key for SQL Statement.
         */
        INSERT_CPE,
        /**
         * Key for SQL Statement.
         */
        INSERT_PROPERTY,
        /**
         * Key for SQL Statement.
         */
        INSERT_REFERENCE,
        /**
         * Key for SQL Statement.
         */
        INSERT_SOFTWARE,
        /**
         * Key for SQL Statement.
         */
        INSERT_VULNERABILITY,
        /**
         * Key for SQL Statement.
         */
        MERGE_PROPERTY,
        /**
         * Key for SQL Statement.
         */
        SELECT_CPE_ENTRIES,
        /**
         * Key for SQL Statement.
         */
        SELECT_CPE_ID,
        /**
         * Key for SQL Statement.
         */
        SELECT_CVE_FROM_SOFTWARE,
        /**
         * Key for SQL Statement.
         */
        SELECT_PROPERTIES,
        /**
         * Key for SQL Statement.
         */
        SELECT_REFERENCES,
        /**
         * Key for SQL Statement.
         */
        SELECT_SOFTWARE,
        /**
         * Key for SQL Statement.
         */
        SELECT_VENDOR_PRODUCT_LIST,
        /**
         * Key for SQL Statement.
         */
        SELECT_VULNERABILITY,
        /**
         * Key for SQL Statement.
         */
        SELECT_VULNERABILITY_ID,
        /**
         * Key for SQL Statement.
         */
        UPDATE_PROPERTY,
        /**
         * Key for SQL Statement.
         */
        UPDATE_VULNERABILITY
    }

    /**
     * Creates a new CveDB object and opens the database connection. Note, the
     * connection must be closed by the caller by calling the close method.
     *
     * @param settings the configured settings
     * @throws DatabaseException thrown if there is an exception opening the
     * database.
     */
    public CveDB(Settings settings) throws DatabaseException {
        this.settings = settings;
        connectionFactory = new ConnectionFactory(settings);
        open();
    }

    /**
     * Tries to determine the product name of the database.
     *
     * @param conn the database connection
     * @return the product name of the database if successful, {@code null} else
     */
    private String determineDatabaseProductName(Connection conn) {
        try {
            final String databaseProductName = conn.getMetaData().getDatabaseProductName().toLowerCase();
            LOGGER.debug("Database product: {}", databaseProductName);
            return databaseProductName;
        } catch (SQLException se) {
            LOGGER.warn("Problem determining database product!", se);
            return null;
        }
    }

    /**
     * Opens the database connection. If the database does not exist, it will
     * create a new one.
     *
     * @throws DatabaseException thrown if there is an error opening the
     * database connection
     */
    private synchronized void open() throws DatabaseException {
        try {
            if (!isOpen()) {
                connection = connectionFactory.getConnection();
                final String databaseProductName = determineDatabaseProductName(this.connection);
                statementBundle = databaseProductName != null
                        ? ResourceBundle.getBundle("data/dbStatements", new Locale(databaseProductName))
                        : ResourceBundle.getBundle("data/dbStatements");
                prepareStatements();
                databaseProperties = new DatabaseProperties(this);
            }
        } catch (DatabaseException e) {
            releaseResources();
            throw e;
        }
    }

    /**
     * Closes the database connection. Close should be called on this object
     * when it is done being used.
     */
    @Override
    public synchronized void close() {
        if (isOpen()) {
            clearCache();
            closeStatements();
            try {
                connection.close();
            } catch (SQLException ex) {
                LOGGER.error("There was an error attempting to close the CveDB, see the log for more details.");
                LOGGER.debug("", ex);
            } catch (Throwable ex) {
                LOGGER.error("There was an exception attempting to close the CveDB, see the log for more details.");
                LOGGER.debug("", ex);
            }
            releaseResources();
            connectionFactory.cleanup();
        }
    }

    /**
     * Releases the resources used by CveDB.
     */
    private synchronized void releaseResources() {
        statementBundle = null;
        preparedStatements.clear();
        databaseProperties = null;
        connection = null;
    }

    /**
     * Returns whether the database connection is open or closed.
     *
     * @return whether the database connection is open or closed
     */
    protected synchronized boolean isOpen() {
        return connection != null;
    }

    /**
     * Prepares all statements to be used.
     *
     * @throws DatabaseException thrown if there is an error preparing the
     * statements
     */
    private void prepareStatements() throws DatabaseException {
        for (PreparedStatementCveDb key : values()) {
            PreparedStatement preparedStatement = null;
            try {
                final String statementString = statementBundle.getString(key.name());
                if (key == INSERT_VULNERABILITY || key == INSERT_CPE) {
                    preparedStatement = connection.prepareStatement(statementString, new String[]{"id"});
                } else {
                    preparedStatement = connection.prepareStatement(statementString);
                }
            } catch (SQLException ex) {
                throw new DatabaseException(ex);
            } catch (MissingResourceException ex) {
                if (!ex.getMessage().contains("key MERGE_PROPERTY")) {
                    throw new DatabaseException(ex);
                }
            }
            if (preparedStatement != null) {
                preparedStatements.put(key, preparedStatement);
            }
        }
    }

    /**
     * Closes all prepared statements.
     */
    private synchronized void closeStatements() {
        for (PreparedStatement preparedStatement : preparedStatements.values()) {
            DBUtils.closeStatement(preparedStatement);
        }
    }

    /**
     * Returns the specified prepared statement.
     *
     * @param key the prepared statement from {@link PreparedStatementCveDb} to
     * return
     * @return the prepared statement
     * @throws SQLException thrown if a SQL Exception occurs
     */
    private synchronized PreparedStatement getPreparedStatement(PreparedStatementCveDb key) throws SQLException {
        if (!preparedStatements.containsKey(key)) {
            return null;
        }
        final PreparedStatement preparedStatement = preparedStatements.get(key);
        preparedStatement.clearParameters();
        return preparedStatement;
    }

    /**
     * Commits all completed transactions.
     *
     * @throws SQLException thrown if a SQL Exception occurs
     */
    @SuppressWarnings("EmptyMethod")
    public synchronized void commit() throws SQLException {
        //temporary remove this as autocommit is on.
        //if (isOpen()) {
        //    connection.commit();
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
        LOGGER.debug("Entering finalize");
        close();
        super.finalize();
    }

    /**
     * Get the value of databaseProperties.
     *
     * @return the value of databaseProperties
     */
    public synchronized DatabaseProperties getDatabaseProperties() {
        return databaseProperties;
    }

    /**
     * Used within the unit tests to reload the database properties.
     *
     * @return the database properties
     */
    protected synchronized DatabaseProperties reloadProperties() {
        databaseProperties = new DatabaseProperties(this);
        return databaseProperties;
    }

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
    public synchronized Set<VulnerableSoftware> getCPEs(String vendor, String product) {
        final Set<VulnerableSoftware> cpe = new HashSet<>();
        ResultSet rs = null;
        try {
            final PreparedStatement ps = getPreparedStatement(SELECT_CPE_ENTRIES);
            ps.setString(1, vendor);
            ps.setString(2, product);
            rs = ps.executeQuery();

            while (rs.next()) {
                final VulnerableSoftware vs = new VulnerableSoftware();
                vs.setCpe(rs.getString(1));
                cpe.add(vs);
            }
        } catch (SQLException ex) {
            LOGGER.error("An unexpected SQL Exception occurred; please see the verbose log for more details.");
            LOGGER.debug("", ex);
        } finally {
            DBUtils.closeResultSet(rs);
        }
        return cpe;
    }

    /**
     * Returns the entire list of vendor/product combinations.
     *
     * @return the entire list of vendor/product combinations
     * @throws DatabaseException thrown when there is an error retrieving the
     * data from the DB
     */
    public synchronized Set<Pair<String, String>> getVendorProductList() throws DatabaseException {
        final Set<Pair<String, String>> data = new HashSet<>();
        ResultSet rs = null;
        try {
            final PreparedStatement ps = getPreparedStatement(SELECT_VENDOR_PRODUCT_LIST);
            rs = ps.executeQuery();
            while (rs.next()) {
                data.add(new Pair<>(rs.getString(1), rs.getString(2)));
            }
        } catch (SQLException ex) {
            final String msg = "An unexpected SQL Exception occurred; please see the verbose log for more details.";
            throw new DatabaseException(msg, ex);
        } finally {
            DBUtils.closeResultSet(rs);
        }
        return data;
    }

    /**
     * Returns a set of properties.
     *
     * @return the properties from the database
     */
    public synchronized Properties getProperties() {
        final Properties prop = new Properties();
        ResultSet rs = null;
        try {
            final PreparedStatement ps = getPreparedStatement(SELECT_PROPERTIES);
            rs = ps.executeQuery();
            while (rs.next()) {
                prop.setProperty(rs.getString(1), rs.getString(2));
            }
        } catch (SQLException ex) {
            LOGGER.error("An unexpected SQL Exception occurred; please see the verbose log for more details.");
            LOGGER.debug("", ex);
        } finally {
            DBUtils.closeResultSet(rs);
        }
        return prop;
    }

    /**
     * Saves a property to the database.
     *
     * @param key the property key
     * @param value the property value
     */
    public synchronized void saveProperty(String key, String value) {
        clearCache();
        try {
            final PreparedStatement mergeProperty = getPreparedStatement(MERGE_PROPERTY);
            if (mergeProperty != null) {
                mergeProperty.setString(1, key);
                mergeProperty.setString(2, value);
                mergeProperty.execute();
            } else {
                // No Merge statement, so doing an Update/Insert...
                final PreparedStatement updateProperty = getPreparedStatement(UPDATE_PROPERTY);
                updateProperty.setString(1, value);
                updateProperty.setString(2, key);
                if (updateProperty.executeUpdate() == 0) {
                    final PreparedStatement insertProperty = getPreparedStatement(INSERT_PROPERTY);
                    insertProperty.setString(1, key);
                    insertProperty.setString(2, value);
                    insertProperty.executeUpdate();
                }
            }
        } catch (SQLException ex) {
            LOGGER.warn("Unable to save property '{}' with a value of '{}' to the database", key, value);
            LOGGER.debug("", ex);
        }
    }

    /**
     * Clears cache. Should be called whenever something is modified. While this
     * is not the optimal cache eviction strategy, this is good enough for
     * typical usage (update DB and then only read) and it is easier to maintain
     * the code.
     * <p>
     * It should be also called when DB is closed.
     * </p>
     */
    private synchronized void clearCache() {
        vulnerabilitiesForCpeCache.clear();
    }

    /**
     * Retrieves the vulnerabilities associated with the specified CPE.
     *
     * @param cpeStr the CPE name
     * @return a list of Vulnerabilities
     * @throws DatabaseException thrown if there is an exception retrieving data
     */
    public synchronized List<Vulnerability> getVulnerabilities(String cpeStr) throws DatabaseException {
        final List<Vulnerability> cachedVulnerabilities = vulnerabilitiesForCpeCache.get(cpeStr);
        if (cachedVulnerabilities != null) {
            LOGGER.debug("Cache hit for {}", cpeStr);
            return cachedVulnerabilities;
        } else {
            LOGGER.debug("Cache miss for {}", cpeStr);
        }
        final VulnerableSoftware cpe = new VulnerableSoftware();
        try {
            cpe.parseName(cpeStr);
        } catch (UnsupportedEncodingException ex) {
            LOGGER.trace("", ex);
        }
        final DependencyVersion detectedVersion = parseDependencyVersion(cpe);
        final List<Vulnerability> vulnerabilities = new ArrayList<>();

        ResultSet rs = null;
        try {
            final PreparedStatement ps = getPreparedStatement(SELECT_CVE_FROM_SOFTWARE);
            ps.setString(1, cpe.getVendor());
            ps.setString(2, cpe.getProduct());
            rs = ps.executeQuery();
            String currentCVE = "";

            final Map<String, Boolean> vulnSoftware = new HashMap<>();
            while (rs.next()) {
                final String cveId = rs.getString(1);
                if (!currentCVE.equals(cveId)) { //check for match and add
                    final Entry<String, Boolean> matchedCPE = getMatchingSoftware(vulnSoftware, cpe.getVendor(), cpe.getProduct(), detectedVersion);
                    if (matchedCPE != null) {
                        final Vulnerability v = getVulnerability(currentCVE);
                        if (v != null) {
                            v.setMatchedCPE(matchedCPE.getKey(), matchedCPE.getValue() ? "Y" : null);
                            vulnerabilities.add(v);
                        }
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
                if (v != null) {
                    v.setMatchedCPE(matchedCPE.getKey(), matchedCPE.getValue() ? "Y" : null);
                    vulnerabilities.add(v);
                }
            }
        } catch (SQLException ex) {
            throw new DatabaseException("Exception retrieving vulnerability for " + cpeStr, ex);
        } finally {
            DBUtils.closeResultSet(rs);
        }
        vulnerabilitiesForCpeCache.put(cpeStr, vulnerabilities);
        return vulnerabilities;
    }

    /**
     * Gets a vulnerability for the provided CVE.
     *
     * @param cve the CVE to lookup
     * @return a vulnerability object
     * @throws DatabaseException if an exception occurs
     */
    public synchronized Vulnerability getVulnerability(String cve) throws DatabaseException {
        ResultSet rsV = null;
        ResultSet rsR = null;
        ResultSet rsS = null;
        Vulnerability vuln = null;

        try {
            final PreparedStatement psV = getPreparedStatement(SELECT_VULNERABILITY);
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
                        cwe += ' ' + name;
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

                final PreparedStatement psR = getPreparedStatement(SELECT_REFERENCES);
                psR.setInt(1, cveId);
                rsR = psR.executeQuery();
                while (rsR.next()) {
                    vuln.addReference(rsR.getString(1), rsR.getString(2), rsR.getString(3));
                }

                final PreparedStatement psS = getPreparedStatement(SELECT_SOFTWARE);
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
    public synchronized void updateVulnerability(Vulnerability vuln) throws DatabaseException {
        clearCache();
        ResultSet rs = null;
        try {
            int vulnerabilityId = 0;
            final PreparedStatement selectVulnerabilityId = getPreparedStatement(SELECT_VULNERABILITY_ID);
            selectVulnerabilityId.setString(1, vuln.getName());
            rs = selectVulnerabilityId.executeQuery();
            if (rs.next()) {
                vulnerabilityId = rs.getInt(1);
                // first delete any existing vulnerability info. We don't know what was updated. yes, slower but atm easier.
                final PreparedStatement deleteReference = getPreparedStatement(DELETE_REFERENCE);
                deleteReference.setInt(1, vulnerabilityId);
                deleteReference.execute();

                final PreparedStatement deleteSoftware = getPreparedStatement(DELETE_SOFTWARE);
                deleteSoftware.setInt(1, vulnerabilityId);
                deleteSoftware.execute();
            }

            DBUtils.closeResultSet(rs);

            if (vulnerabilityId != 0) {
                if (vuln.getDescription().contains("** REJECT **")) {
                    final PreparedStatement deleteVulnerability = getPreparedStatement(DELETE_VULNERABILITY);
                    deleteVulnerability.setInt(1, vulnerabilityId);
                    deleteVulnerability.executeUpdate();
                } else {
                    final PreparedStatement updateVulnerability = getPreparedStatement(UPDATE_VULNERABILITY);
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
                final PreparedStatement insertVulnerability = getPreparedStatement(INSERT_VULNERABILITY);
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
                }
            }

            PreparedStatement insertReference = getPreparedStatement(INSERT_REFERENCE);
            int countReferences = 0;
            for (Reference r : vuln.getReferences()) {
                insertReference.setInt(1, vulnerabilityId);
                insertReference.setString(2, r.getName());
                insertReference.setString(3, r.getUrl());
                insertReference.setString(4, r.getSource());
                if (isBatchInsertEnabled()) {
                    insertReference.addBatch();
                    countReferences++;
                    if (countReferences % getBatchSize() == 0) {
                        insertReference.executeBatch();
                        insertReference = getPreparedStatement(INSERT_REFERENCE);
                        LOGGER.trace(getLogForBatchInserts(countReferences, "Completed %s batch inserts to references table: %s"));
                        countReferences = 0;
                    } else if (countReferences == vuln.getReferences().size()) {
                        if (LOGGER.isTraceEnabled()) {
                            LOGGER.trace(getLogForBatchInserts(countReferences, "Completed %s batch inserts to reference table: %s"));
                        }
                        insertReference.executeBatch();
                        countReferences = 0;
                    }
                } else {
                    insertReference.execute();
                }
            }

            PreparedStatement insertSoftware = getPreparedStatement(INSERT_SOFTWARE);
            int countSoftware = 0;
            for (VulnerableSoftware vulnerableSoftware : vuln.getVulnerableSoftware()) {
                int cpeProductId = 0;
                final PreparedStatement selectCpeId = getPreparedStatement(SELECT_CPE_ID);
                selectCpeId.setString(1, vulnerableSoftware.getName());
                try {
                    rs = selectCpeId.executeQuery();
                    if (rs.next()) {
                        cpeProductId = rs.getInt(1);
                    }
                } catch (SQLException ex) {
                    throw new DatabaseException("Unable to get primary key for new cpe: " + vulnerableSoftware.getName(), ex);
                } finally {
                    DBUtils.closeResultSet(rs);
                }

                if (cpeProductId == 0) {
                    final PreparedStatement insertCpe = getPreparedStatement(INSERT_CPE);
                    insertCpe.setString(1, vulnerableSoftware.getName());
                    insertCpe.setString(2, vulnerableSoftware.getVendor());
                    insertCpe.setString(3, vulnerableSoftware.getProduct());
                    insertCpe.executeUpdate();
                    cpeProductId = DBUtils.getGeneratedKey(insertCpe);
                }
                if (cpeProductId == 0) {
                    throw new DatabaseException("Unable to retrieve cpeProductId - no data returned");
                }

                insertSoftware.setInt(1, vulnerabilityId);
                insertSoftware.setInt(2, cpeProductId);

                if (vulnerableSoftware.getPreviousVersion() == null) {
                    insertSoftware.setNull(3, java.sql.Types.VARCHAR);
                } else {
                    insertSoftware.setString(3, vulnerableSoftware.getPreviousVersion());
                }
                if (isBatchInsertEnabled()) {
                    insertSoftware.addBatch();
                    countSoftware++;
                    if (countSoftware % getBatchSize() == 0) {
                        executeBatch(vuln, vulnerableSoftware, insertSoftware);
                        insertSoftware = getPreparedStatement(INSERT_SOFTWARE);
                        LOGGER.trace(getLogForBatchInserts(countSoftware, "Completed %s batch inserts software table: %s"));
                        countSoftware = 0;
                    } else if (countSoftware == vuln.getVulnerableSoftware().size()) {
                        if (LOGGER.isTraceEnabled()) {
                            LOGGER.trace(getLogForBatchInserts(countSoftware, "Completed %s batch inserts software table: %s"));
                            countReferences = 0;
                        }
                        executeBatch(vuln, vulnerableSoftware, insertSoftware);
                    }
                } else {
                    try {
                        insertSoftware.execute();
                    } catch (SQLException ex) {
                        if (ex.getMessage().contains("Duplicate entry")) {
                            final String msg = String.format("Duplicate software key identified in '%s:%s'", vuln.getName(), vuln.getName());
                            LOGGER.info(msg, ex);
                        } else {
                            throw ex;
                        }
                    }
                }
            }
        } catch (SQLException ex) {
            final String msg = String.format("Error updating '%s'", vuln.getName());
            LOGGER.debug(msg, ex);
            throw new DatabaseException(msg, ex);
        } finally {
            DBUtils.closeResultSet(rs);
        }
    }

    /**
     * Returns the size of the batch.
     *
     * @return the size of the batch
     */
    private int getBatchSize() {
        int max;
        try {
            max = settings.getInt(Settings.KEYS.MAX_BATCH_SIZE);
        } catch (InvalidSettingException pE) {
            max = 1000;
        }
        return max;
    }

    /**
     * Determines whether or not batch insert is enabled.
     *
     * @return <code>true</code> if batch insert is enabled; otherwise
     * <code>false</code>
     */
    private boolean isBatchInsertEnabled() {
        boolean batch = false;
        try {
            batch = settings.getBoolean(Settings.KEYS.ENABLE_BATCH_UPDATES);
        } catch (InvalidSettingException pE) {
            //If there's no configuration, default is to not perform batch inserts
            batch = false;
        }
        return batch;
    }

    /**
     * Generates a logging message for batch inserts.
     *
     * @param pCountReferences the number of batch statements executed
     * @param pFormat a Java String.format string
     * @return the formated string
     */
    private String getLogForBatchInserts(int pCountReferences, String pFormat) {
        return String.format(pFormat, pCountReferences, new Date());
    }

    /**
     * Executes batch inserts of vulnerabilities when property
     * database.batchinsert.maxsize is reached.
     *
     * @param pVulnerability the vulnerability
     * @param pVulnerableSoftware the vulnerable software
     * @param pInsertSoftware the prepared statement to batch execute
     * @throws SQLException thrown when the batch cannot be executed
     */
    private void executeBatch(Vulnerability pVulnerability, VulnerableSoftware pVulnerableSoftware, PreparedStatement pInsertSoftware)
            throws SQLException {
        try {
            pInsertSoftware.executeBatch();
        } catch (SQLException ex) {
            if (ex.getMessage().contains("Duplicate entry")) {
                final String msg = String.format("Duplicate software key identified in '%s:%s'",
                        pVulnerability.getName(), pVulnerableSoftware.getName());
                LOGGER.info(msg, ex);
            } else {
                throw ex;
            }
        }
    }

    /**
     * Checks to see if data exists so that analysis can be performed.
     *
     * @return <code>true</code> if data exists; otherwise <code>false</code>
     */
    public synchronized boolean dataExists() {
        ResultSet rs = null;
        try {
            final PreparedStatement cs = getPreparedStatement(COUNT_CPE);
            rs = cs.executeQuery();
            if (rs.next() && rs.getInt(1) > 0) {
                return true;
            }
        } catch (Exception ex) {
            String dd;
            try {
                dd = settings.getDataDirectory().getAbsolutePath();
            } catch (IOException ex1) {
                dd = settings.getString(Settings.KEYS.DATA_DIRECTORY);
            }
            LOGGER.error("Unable to access the local database.\n\nEnsure that '{}' is a writable directory. "
                    + "If the problem persist try deleting the files in '{}' and running {} again. If the problem continues, please "
                    + "create a log file (see documentation at http://jeremylong.github.io/DependencyCheck/) and open a ticket at "
                    + "https://github.com/jeremylong/DependencyCheck/issues and include the log file.\n\n",
                    dd, dd, settings.getString(Settings.KEYS.APPLICATION_NAME));
            LOGGER.debug("", ex);
        } finally {
            DBUtils.closeResultSet(rs);
        }
        return false;
    }

    /**
     * It is possible that orphaned rows may be generated during database
     * updates. This should be called after all updates have been completed to
     * ensure orphan entries are removed.
     */
    public synchronized void cleanupDatabase() {
        clearCache();
        try {
            final PreparedStatement ps = getPreparedStatement(CLEANUP_ORPHANS);
            if (ps != null) {
                ps.executeUpdate();
            }
        } catch (SQLException ex) {
            LOGGER.error("An unexpected SQL Exception occurred; please see the verbose log for more details.");
            LOGGER.debug("", ex);
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
     * @param vulnerableSoftware a map of the vulnerable software with a boolean
     * indicating if all previous versions are affected
     * @param identifiedVersion the identified version of the dependency being
     * analyzed
     * @return true if the identified version is affected, otherwise false
     */
    protected Entry<String, Boolean> getMatchingSoftware(Map<String, Boolean> vulnerableSoftware, String vendor, String product,
            DependencyVersion identifiedVersion) {

        final boolean isVersionTwoADifferentProduct = "apache".equals(vendor) && "struts".equals(product);

        final Set<String> majorVersionsAffectingAllPrevious = new HashSet<>();
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
                if (canSkipVersions && majorVersionMatch != null && !majorVersionMatch.equals(v.getVersionParts().get(0))) {
                    continue;
                }
                //this can't dereference a null 'identifiedVersion' because if it was null we would have exited
                //in the above loop or just after loop (if matchesAnyPrevious return null).
                if (identifiedVersion != null && identifiedVersion.equals(v)) {
                    return entry;
                }
            }
        }
        for (Entry<String, Boolean> entry : vulnerableSoftware.entrySet()) {
            if (entry.getValue()) {
                final DependencyVersion v = parseDependencyVersion(entry.getKey());
                //this can't dereference a null 'majorVersionMatch' as canSkipVersions accounts for this.
                if (canSkipVersions && majorVersionMatch != null && !majorVersionMatch.equals(v.getVersionParts().get(0))) {
                    continue;
                }
                //this can't dereference a null 'identifiedVersion' because if it was null we would have exited
                //in the above loop or just after loop (if matchesAnyPrevious return null).
                if (entry.getValue() && identifiedVersion != null && identifiedVersion.compareTo(v) <= 0
                        && !(isVersionTwoADifferentProduct && !identifiedVersion.getVersionParts().get(0).equals(v.getVersionParts().get(0)))) {
                    return entry;
                }
            }
        }
        return null;
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
            LOGGER.trace("", ex);
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
        final DependencyVersion cpeVersion;
        if (cpe.getVersion() != null && !cpe.getVersion().isEmpty()) {
            final String versionText;
            if (cpe.getUpdate() != null && !cpe.getUpdate().isEmpty()) {
                versionText = String.format("%s.%s", cpe.getVersion(), cpe.getUpdate());
            } else {
                versionText = cpe.getVersion();
            }
            cpeVersion = DependencyVersionUtil.parseVersion(versionText, true);
        } else {
            cpeVersion = new DependencyVersion("-");
        }
        return cpeVersion;
    }

    /**
     * This method is only referenced in unused code.
     * <p>
     * Deletes unused dictionary entries from the database.
     * </p>
     */
    public synchronized void deleteUnusedCpe() {
        clearCache();
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(statementBundle.getString("DELETE_UNUSED_DICT_CPE"));
            ps.executeUpdate();
        } catch (SQLException ex) {
            LOGGER.error("Unable to delete CPE dictionary entries", ex);
        } finally {
            DBUtils.closeStatement(ps);
        }
    }

    /**
     * This method is only referenced in unused code and will likely break on
     * MySQL if ever used due to the MERGE statement.
     * <p>
     * Merges CPE entries into the database.
     * </p>
     *
     * @param cpe the CPE identifier
     * @param vendor the CPE vendor
     * @param product the CPE product
     */
    public synchronized void addCpe(String cpe, String vendor, String product) {
        clearCache();
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(statementBundle.getString("ADD_DICT_CPE"));
            ps.setString(1, cpe);
            ps.setString(2, vendor);
            ps.setString(3, product);
            ps.executeUpdate();
        } catch (SQLException ex) {
            LOGGER.error("Unable to add CPE dictionary entry", ex);
        } finally {
            DBUtils.closeStatement(ps);
        }
    }
}
