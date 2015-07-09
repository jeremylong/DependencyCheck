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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Jeremy Long
 */
public abstract class BaseUpdater {

    /**
     * Static logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(BaseUpdater.class);
    /**
     * Information about the timestamps and URLs for data that needs to be updated.
     */
    private DatabaseProperties properties;
    /**
     * Reference to the Cve Database.
     */
    private CveDB cveDB = null;

    protected CveDB getCveDB() {
        return cveDB;
    }

    protected DatabaseProperties getProperties() {
        return properties;
    }

    /**
     * Closes the CVE and CPE data stores.
     */
    protected void closeDataStores() {
        if (cveDB != null) {
            try {
                cveDB.close();
            } catch (Throwable ignore) {
                LOGGER.trace("Error closing the database", ignore);
            }
        }
    }

    /**
     * Opens the data store.
     *
     * @throws UpdateException thrown if a data store cannot be opened
     */
    protected final void openDataStores() throws UpdateException {
        if (cveDB != null) {
            return;
        }
        try {
            cveDB = new CveDB();
            cveDB.open();
        } catch (DatabaseException ex) {
            closeDataStores();
            LOGGER.debug("Database Exception opening databases", ex);
            throw new UpdateException("Error updating the database, please see the log file for more details.");
        }
        properties = cveDB.getDatabaseProperties();
    }
}
