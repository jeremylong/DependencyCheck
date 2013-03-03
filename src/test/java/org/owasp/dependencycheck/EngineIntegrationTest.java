/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck;

import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class EngineIntegrationTest {

    public EngineIntegrationTest() throws Exception {
        org.owasp.dependencycheck.data.nvdcve.BaseDBTestCase.ensureDBExists();
        org.owasp.dependencycheck.data.cpe.BaseIndexTestCase.ensureIndexExists();
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of scan method, of class Engine.
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testScan() throws Exception {
        String path = "./src/test/resources/";
        Engine instance = new Engine();
        instance.scan(path);
        assertTrue(instance.getDependencies().size() > 0);
        instance.analyzeDependencies();
        ReportGenerator rg = new ReportGenerator("DependencyCheck",
                instance.getDependencies(), instance.getAnalyzers());
        rg.generateReports("./target/", "HTML");
    }
}
