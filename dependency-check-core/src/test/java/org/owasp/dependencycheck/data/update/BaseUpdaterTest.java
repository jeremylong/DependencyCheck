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

import org.junit.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 *
 * @author Jeremy Long
 */
public class BaseUpdaterTest extends BaseDBTestCase {

    /**
     * Test of getCveDB method, of class BaseUpdater.
     */
    @Test
    public void testGetCveDB() {
        BaseUpdater instance = new BaseUpdaterImpl();
        CveDB expResult = null;
        CveDB result = instance.getCveDB();
        assertEquals(expResult, result);
    }

    /**
     * Test of getProperties method, of class BaseUpdater.
     *
     * @throws org.owasp.dependencycheck.data.update.exception.UpdateException
     * thrown if there is an error getting the properties
     */
    @Test
    public void testGetProperties() throws UpdateException {
        BaseUpdater instance = null;
        try {
            instance = new BaseUpdaterImpl();
            instance.openDataStores();

            DatabaseProperties result = instance.getProperties();
            assertTrue(result.getProperties().keySet().size() > 1);
        } finally {
            if (instance != null) {
                instance.closeDataStores();
            }
        }
    }

    /**
     * Test of closeDataStores method, of class BaseUpdater.
     */
    @Test
    public void testCloseDataStores() {
        BaseUpdater instance = null;
        try {
            instance = new BaseUpdaterImpl();
            instance.openDataStores();
        } catch (UpdateException ex) {
            fail(ex.getMessage());
        } finally {
            if (instance != null) {
                instance.closeDataStores();
            }
        }
    }

    /**
     * Test of openDataStores method, of class BaseUpdater.
     */
    @Test
    public void testOpenDataStores() {
        BaseUpdater instance = null;
        try {
            instance = new BaseUpdaterImpl();
            instance.openDataStores();
        } catch (UpdateException ex) {
            fail(ex.getMessage());
        } finally {
            if (instance != null) {
                instance.closeDataStores();
            }
        }
    }

    public class BaseUpdaterImpl extends BaseUpdater {
    }

}
