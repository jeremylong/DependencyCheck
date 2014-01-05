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

/**
 * When implementing this, use code from the following to load the driver.
 * http://stackoverflow.com/questions/5674637/loading-jdbc-driver-at-runtime
 *
 *
 * @author Jeremy Long (jeremy.long@owasp.org)
 */
public final class ConnectionFactory {

    /**
     * Private constructor for this factory class; no instance is ever needed.
     */
    private ConnectionFactory() {
    }

    public static Connection getConnection() {
        return null;
    }
}
