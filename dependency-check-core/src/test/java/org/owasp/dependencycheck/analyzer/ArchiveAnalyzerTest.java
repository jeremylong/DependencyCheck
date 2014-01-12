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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.util.HashSet;
import java.util.Set;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.cpe.BaseIndexTestCase;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class ArchiveAnalyzerTest extends BaseIndexTestCase {

    public ArchiveAnalyzerTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test of getSupportedExtensions method, of class ArchiveAnalyzer.
     */
    @Test
    public void testGetSupportedExtensions() {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        Set expResult = new HashSet<String>();
        expResult.add("zip");
        expResult.add("war");
        expResult.add("ear");
        expResult.add("tar");
        expResult.add("gz");
        expResult.add("tgz");
        Set result = instance.getSupportedExtensions();
        assertEquals(expResult, result);
    }

    /**
     * Test of getName method, of class ArchiveAnalyzer.
     */
    @Test
    public void testGetName() {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        String expResult = "Archive Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of supportsExtension method, of class ArchiveAnalyzer.
     */
    @Test
    public void testSupportsExtension() {
        String extension = "7z"; //not supported
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        boolean expResult = false;
        boolean result = instance.supportsExtension(extension);
        assertEquals(expResult, result);

        extension = "war"; //supported
        expResult = true;
        result = instance.supportsExtension(extension);
        assertEquals(expResult, result);

        extension = "ear"; //supported
        result = instance.supportsExtension(extension);
        assertEquals(expResult, result);

        extension = "zip"; //supported
        result = instance.supportsExtension(extension);
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class ArchiveAnalyzer.
     */
    @Test
    public void testGetAnalysisPhase() {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.INITIAL;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of initialize and close methods, of class ArchiveAnalyzer.
     */
    @Test
    public void testInitialize() throws Exception {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        instance.initialize();

        instance.close();

        //no exception means things worked.
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     */
    @Test
    public void testAnalyze() throws Exception {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        try {
            instance.initialize();

            File file = new File(this.getClass().getClassLoader().getResource("daytrader-ear-2.1.7.ear").getPath());
            Dependency dependency = new Dependency(file);
            Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            Engine engine = new Engine();

            int initial_size = engine.getDependencies().size();
            instance.analyze(dependency, engine);
            int ending_size = engine.getDependencies().size();

            assertTrue(initial_size < ending_size);

        } finally {
            instance.close();
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     */
    @Test
    public void testAnalyzeTar() throws Exception {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        try {
            instance.initialize();

            File file = new File(this.getClass().getClassLoader().getResource("file.tar").getPath());
            Dependency dependency = new Dependency(file);
            Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            Engine engine = new Engine();

            int initial_size = engine.getDependencies().size();
            instance.analyze(dependency, engine);
            int ending_size = engine.getDependencies().size();

            assertTrue(initial_size < ending_size);

        } finally {
            instance.close();
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     */
    @Test
    public void testAnalyzeTarGz() throws Exception {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        try {
            instance.initialize();

            File file = new File(this.getClass().getClassLoader().getResource("file.tar.gz").getPath());
            //Dependency dependency = new Dependency(file);
            Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            Engine engine = new Engine();

            int initial_size = engine.getDependencies().size();
            //instance.analyze(dependency, engine);
            engine.scan(file);
            engine.analyzeDependencies();
            int ending_size = engine.getDependencies().size();

            assertTrue(initial_size < ending_size);

        } finally {
            instance.close();
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     */
    @Test
    public void testAnalyzeTgz() throws Exception {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        try {
            instance.initialize();

            File file = new File(this.getClass().getClassLoader().getResource("file.tgz").getPath());
            Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            Engine engine = new Engine();

            int initial_size = engine.getDependencies().size();
            engine.scan(file);
            engine.analyzeDependencies();
            int ending_size = engine.getDependencies().size();

            assertTrue(initial_size < ending_size);

        } finally {
            instance.close();
        }
    }

    /**
     * Test of analyze method, of class ArchiveAnalyzer.
     */
    @Test
    public void testAnalyze_badZip() throws Exception {
        ArchiveAnalyzer instance = new ArchiveAnalyzer();
        try {
            instance.initialize();

            File file = new File(this.getClass().getClassLoader().getResource("test.zip").getPath());
            Dependency dependency = new Dependency(file);
            Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            Engine engine = new Engine();
            int initial_size = engine.getDependencies().size();
//            boolean failed = false;
//            try {
            instance.analyze(dependency, engine);
//            } catch (java.lang.UnsupportedClassVersionError ex) {
//                failed = true;
//            }
//            assertTrue(failed);
            int ending_size = engine.getDependencies().size();
            assertEquals(initial_size, ending_size);
        } finally {
            instance.close();
        }
    }
}
