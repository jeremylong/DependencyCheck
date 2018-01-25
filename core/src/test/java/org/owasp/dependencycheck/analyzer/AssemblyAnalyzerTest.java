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
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;
import org.junit.After;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Assume;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeNotNull;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.dependency.EvidenceType;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.FileUtils;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tests for the AssemblyAnalyzer.
 *
 * @author colezlaw
 *
 */
public class AssemblyAnalyzerTest extends BaseTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(AssemblyAnalyzerTest.class);

    private static final String LOG_KEY = "org.slf4j.simpleLogger.org.owasp.dependencycheck.analyzer.AssemblyAnalyzer";

    private AssemblyAnalyzer analyzer;

    /**
     * Sets up the analyzer.
     *
     * @throws Exception if anything goes sideways
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        try {
            analyzer = new AssemblyAnalyzer();
            analyzer.initialize(getSettings());
            analyzer.accept(new File("test.dll")); // trick into "thinking it is active"
            analyzer.prepare(null);
            assertGrokAssembly();
        } catch (Exception e) {
            if (e.getMessage().contains("Could not execute .NET AssemblyAnalyzer")) {
                LOGGER.warn("Exception setting up AssemblyAnalyzer. Tests will be incomplete");
            } else {
                LOGGER.warn("Exception setting up AssemblyAnalyzer. Tests will be incomplete");
            }
            Assume.assumeNoException("Is mono installed? TESTS WILL BE INCOMPLETE", e);
        }
    }

    private void assertGrokAssembly() throws IOException {
        // There must be an .exe and a .config files created in the temp
        // directory and they must match the resources they were created from.
        File grokAssemblyExeFile = null;
        File grokAssemblyConfigFile = null;

        File tempDirectory = getSettings().getTempDirectory();
        for (File file : tempDirectory.listFiles()) {
            String filename = file.getName();
            if (filename.startsWith("GKA") && filename.endsWith(".exe")) {
                grokAssemblyExeFile = file;
                break;
            }
        }
        assertTrue("The GrokAssembly executable was not created.", grokAssemblyExeFile.isFile());
        grokAssemblyConfigFile = new File(grokAssemblyExeFile.getPath() + ".config");
        assertTrue("The GrokAssembly config was not created.", grokAssemblyConfigFile.isFile());

        assertFileContent("The GrokAssembly executable has incorrect content.", "GrokAssembly.exe", grokAssemblyExeFile);
        assertFileContent("The GrokAssembly config has incorrect content.", "GrokAssembly.exe.config", grokAssemblyConfigFile);
    }

    private void assertFileContent(String message, String expectedResourceName, File actualFile) throws IOException {
        try (InputStream expectedStream = FileUtils.getResourceAsStream(expectedResourceName);
                InputStream actualStream = new FileInputStream(actualFile)) {
            byte[] expectedBytes = IOUtils.toByteArray(expectedStream);
            byte[] actualBytes = IOUtils.toByteArray(actualStream);
            assertArrayEquals(message, expectedBytes, actualBytes);
        }
    }

    /**
     * Tests to make sure the name is correct.
     */
    @Test
    public void testGetName() {
        assertEquals("Assembly Analyzer", analyzer.getName());
    }

    @Test
    public void testAnalysis() throws Exception {
        assumeNotNull(analyzer.buildArgumentList());
        File f = BaseTest.getResourceAsFile(this, "GrokAssembly.exe");
        Dependency d = new Dependency(f);
        analyzer.analyze(d, null);
        assertTrue(d.contains(EvidenceType.VENDOR, new Evidence("grokassembly", "vendor", "OWASP", Confidence.HIGH)));
        assertTrue(d.contains(EvidenceType.PRODUCT, new Evidence("grokassembly", "product", "GrokAssembly", Confidence.HIGH)));
    }

    @Test
    public void testLog4Net() throws Exception {
        assumeNotNull(analyzer.buildArgumentList());
        File f = BaseTest.getResourceAsFile(this, "log4net.dll");

        Dependency d = new Dependency(f);
        analyzer.analyze(d, null);
        assertTrue(d.contains(EvidenceType.VERSION, new Evidence("grokassembly", "version", "1.2.13.0", Confidence.HIGHEST)));
        assertTrue(d.contains(EvidenceType.VENDOR, new Evidence("grokassembly", "vendor", "The Apache Software Foundation", Confidence.HIGH)));
        assertTrue(d.contains(EvidenceType.PRODUCT, new Evidence("grokassembly", "product", "log4net", Confidence.HIGH)));
    }

    @Test
    public void testNonexistent() {
        assumeNotNull(analyzer.buildArgumentList());

        // Tweak the log level so the warning doesn't show in the console
        String oldProp = System.getProperty(LOG_KEY, "info");
        File f = BaseTest.getResourceAsFile(this, "log4net.dll");
        File test = new File(f.getParent(), "nonexistent.dll");
        Dependency d = new Dependency(test);

        try {
            analyzer.analyze(d, null);
            fail("Expected an AnalysisException");
        } catch (AnalysisException ae) {
            assertTrue(ae.getMessage().contains("nonexistent.dll does not exist and cannot be analyzed by dependency-check"));
        } finally {
            System.setProperty(LOG_KEY, oldProp);
        }
    }

    @Test
    public void testWithSettingMono() throws Exception {

        //This test doesn't work on Windows.
        assumeFalse(System.getProperty("os.name").startsWith("Windows"));

        String oldValue = getSettings().getString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH);
        // if oldValue is null, that means that neither the system property nor the setting has
        // been set. If that's the case, then we have to make it such that when we recover,
        // null still comes back. But you can't put a null value in a HashMap, so we have to set
        // the system property rather than the setting.
        if (oldValue == null) {
            System.setProperty(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH, "/yooser/bine/mono");
        } else {
            getSettings().setString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH, "/yooser/bine/mono");
        }

        String oldProp = System.getProperty(LOG_KEY, "info");
        try {
            // Tweak the logging to swallow the warning when testing
            System.setProperty(LOG_KEY, "error");
            // Have to make a NEW analyzer because during setUp, it would have gotten the correct one
            AssemblyAnalyzer aanalyzer = new AssemblyAnalyzer();
            aanalyzer.initialize(getSettings());
            aanalyzer.accept(new File("test.dll")); // trick into "thinking it is active"
            aanalyzer.prepare(null);
            fail("Expected an InitializationException");
        } catch (InitializationException ae) {
            assertEquals("An error occurred with the .NET AssemblyAnalyzer", ae.getMessage());
        } finally {
            System.setProperty(LOG_KEY, oldProp);
            // Recover the logger
            // Now recover the way we came in. If we had to set a System property, delete it. Otherwise,
            // reset the old value
            if (oldValue == null) {
                System.getProperties().remove(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH);
            } else {
                getSettings().setString(Settings.KEYS.ANALYZER_ASSEMBLY_MONO_PATH, oldValue);
            }
        }
    }

    @After
    @Override
    public void tearDown() throws Exception {
        try {
            analyzer.closeAnalyzer();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        } finally {
            super.tearDown();
        }
    }
}
