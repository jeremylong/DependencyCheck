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
package org.owasp.dependencycheck;

import org.junit.After;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class EngineIntegrationTest extends BaseTest {

    @Before
    public void setUp() throws Exception {
        org.owasp.dependencycheck.data.nvdcve.BaseDBTestCase.ensureDBExists();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of scan method, of class Engine.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testScan() throws Exception {
        String testClasses = "target/test-classes/*.zip";
        boolean autoUpdate = Settings.getBoolean(Settings.KEYS.AUTO_UPDATE);
        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        Engine instance = new Engine();
        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, autoUpdate);
        instance.scan(testClasses);
        assertTrue(instance.getDependencies().size() > 0);
        for (Dependency d : instance.getDependencies()) {
            assertTrue("non-zip file collected " + d.getFileName(), d.getFileName().toLowerCase().endsWith(".zip"));
        }
        instance.cleanup();
    }

    /**
     * Test running the entire engine.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testEngine() throws Exception {
        String testClasses = "target/test-classes";
        boolean autoUpdate = Settings.getBoolean(Settings.KEYS.AUTO_UPDATE);
        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        Engine instance = new Engine();
        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, autoUpdate);
        instance.scan(testClasses);
        assertTrue(instance.getDependencies().size() > 0);
        instance.analyzeDependencies();
        CveDB cveDB = new CveDB();
        cveDB.open();
        DatabaseProperties dbProp = cveDB.getDatabaseProperties();
        cveDB.close();
        ReportGenerator rg = new ReportGenerator("DependencyCheck",
                instance.getDependencies(), instance.getAnalyzers(), dbProp);
        rg.generateReports("./target/", "ALL");
        instance.cleanup();
    }
}
