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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvdcve;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * <p>
 * Driver shim to get around the class loader issue with the DriverManager. The following code is a nearly identical
 * copy (with more comments and a few more methods implemented) of the DriverShim from:</p>
 * <blockquote>http://www.kfu.com/~nsayer/Java/dyn-jdbc.html</blockquote>
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 * @see java.sql.Driver
 */
class DriverShim implements Driver {

    /**
     * The database driver being wrapped.
     */
    private final Driver driver;

    /**
     * Constructs a new wrapper around a Driver.
     *
     * @param driver the database driver to wrap
     */
    DriverShim(Driver driver) {
        this.driver = driver;
    }

    /**
     * Wraps the underlying driver's call to acceptsURL. Returns whether or not the driver can open a connection to the
     * given URL.
     *
     * @param url the URL of the database
     * @return true if the wrapped driver can connect to the specified URL
     * @throws SQLException thrown if there is an error connecting to the database
     * @see java.sql.Driver#acceptsURL(java.lang.String)
     */
    @Override
    public boolean acceptsURL(String url) throws SQLException {
        return this.driver.acceptsURL(url);
    }

    /**
     * Returns the wrapped driver's major version number.
     *
     * @return the wrapped driver's major version number
     * @see java.sql.Driver#getMajorVersion()
     */
    @Override
    public int getMajorVersion() {
        return this.driver.getMajorVersion();
    }

    /**
     * Returns the wrapped driver's minor version number.
     *
     * @return the wrapped driver's minor version number
     * @see java.sql.Driver#getMinorVersion()
     */
    @Override
    public int getMinorVersion() {
        return this.driver.getMinorVersion();
    }

    /**
     * Returns whether or not the wrapped driver is jdbcCompliant.
     *
     * @return true if the wrapped driver is JDBC compliant; otherwise false
     * @see java.sql.Driver#jdbcCompliant()
     */
    @Override
    public boolean jdbcCompliant() {
        return this.driver.jdbcCompliant();
    }

    /**
     * Wraps the call to the underlying driver's connect method.
     *
     * @param url the URL of the database
     * @param info a collection of string/value pairs
     * @return a Connection object
     * @throws SQLException thrown if there is an error connecting to the database
     * @see java.sql.Driver#connect(java.lang.String, java.util.Properties)
     */
    @Override
    public Connection connect(String url, Properties info) throws SQLException {
        return this.driver.connect(url, info);
    }

    /**
     * Wraps the call to the underlying driver's getPropertyInfo method.
     *
     * @param url the URL of the database
     * @param info a collection of string/value pairs
     * @return an array of DriverPropertyInfo objects
     * @throws SQLException thrown if there is an error accessing the database
     * @see java.sql.Driver#getPropertyInfo(java.lang.String, java.util.Properties)
     */
    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {
        return this.driver.getPropertyInfo(url, info);
    }

    /**
     * Wraps the call to the underlying driver's getParentLogger method.
     *
     * @return the parent's Logger
     * @throws SQLException thrown if there is an error accessing the database
     * @see java.sql.Driver#getParentLogger()
     */
    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        return this.driver.getParentLogger();
    }

    /**
     * Standard implementation of hashCode.
     *
     * @return the hashCode of the object
     */
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + (this.driver != null ? this.driver.hashCode() : 0);
        return hash;
    }

    /**
     * Standard implementation of equals.
     *
     * @param obj the object to compare
     * @return returns true if the objects are equal; otherwise false
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final DriverShim other = (DriverShim) obj;
        return this.driver == other.driver || (this.driver != null && this.driver.equals(other.driver));
    }

    /**
     * Standard implementation of toString().
     *
     * @return the String representation of the object
     */
    @Override
    public String toString() {
        return "DriverShim{" + "driver=" + driver + '}';
    }
}
