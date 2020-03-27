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
 * Copyright (c) 2015 Institute for Defense Analyses. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import edu.emory.mathcs.backport.java.util.Arrays;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.exception.InitializationException;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.owasp.dependencycheck.dependency.EvidenceType;

/**
 * Unit tests for {@link RubyBundleAuditAnalyzer}.
 *
 * @author Dale Visser
 */
public class RubyBundleAuditAnalyzerIT extends BaseDBTestCase {

    private static final Logger LOGGER = LoggerFactory.getLogger(RubyBundleAuditAnalyzerIT.class);

    /**
     * The analyzer to test.
     */
    private RubyBundleAuditAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        analyzer = new RubyBundleAuditAnalyzer();
        analyzer.initialize(getSettings());
        analyzer.setFilesMatched(true);
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    @Override
    public void tearDown() throws Exception {
        if (analyzer != null) {
            analyzer.close();
            analyzer = null;
        }
        super.tearDown();
    }

    /**
     * Test Ruby Gemspec name.
     */
    @Test
    public void testGetName() {
        assertThat(analyzer.getName(), is("Ruby Bundle Audit Analyzer"));
    }

    /**
     * Test Ruby Bundler Audit file support.
     */
    @Test
    public void testSupportsFiles() {
        assertThat(analyzer.accept(new File("Gemfile.lock")), is(true));
    }

    /**
     * Test Ruby BundlerAudit analysis.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalysis() throws AnalysisException, DatabaseException {
        try (Engine engine = new Engine(getSettings())) {
            engine.openDatabase();
            analyzer.prepare(engine);
            final String resource = "ruby/vulnerable/gems/rails-4.1.15/Gemfile.lock";
            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, resource));
            analyzer.analyze(result, engine);
            final Dependency[] dependencies = engine.getDependencies();
            final int size = dependencies.length;
            assertTrue(size >= 1);
            boolean found = false;
            for (Dependency dependency : dependencies) {
                found = dependency.getEvidence(EvidenceType.PRODUCT).toString().toLowerCase().contains("redcarpet");
                found &= dependency.getEvidence(EvidenceType.VERSION).toString().toLowerCase().contains("2.2.2");
                found &= dependency.getFilePath().endsWith(resource);
                found &= dependency.getFileName().equals("Gemfile.lock");
                if (found) {
                    break;
                }
            }
            assertTrue("redcarpet was not identified", found);

        } catch (InitializationException | DatabaseException | AnalysisException e) {
            LOGGER.warn("Exception setting up RubyBundleAuditAnalyzer. Make sure Ruby gem bundle-audit is installed. You may also need to set property \"analyzer.bundle.audit.path\".");
            Assume.assumeNoException("Exception setting up RubyBundleAuditAnalyzer; bundle audit may not be installed, or property \"analyzer.bundle.audit.path\" may not be set.", e);
        }
    }

    /**
     * Test Ruby addCriticalityToVulnerability
     */
    @Test
    public void testAddCriticalityToVulnerability() throws AnalysisException, DatabaseException {
        try (Engine engine = new Engine(getSettings())) {
            engine.doUpdates(true);
            analyzer.prepare(engine);

            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                    "ruby/vulnerable/gems/sinatra/Gemfile.lock"));
            analyzer.analyze(result, engine);
            Dependency dependency = engine.getDependencies()[0];
            Vulnerability vulnerability = dependency.getVulnerabilities(true).iterator().next();
            assertEquals(5.0f, vulnerability.getCvssV2().getScore(), 0.0);

        } catch (InitializationException | DatabaseException | AnalysisException | UpdateException e) {
            LOGGER.warn("Exception setting up RubyBundleAuditAnalyzer. Make sure Ruby gem bundle-audit is installed. You may also need to set property \"analyzer.bundle.audit.path\".");
            Assume.assumeNoException("Exception setting up RubyBundleAuditAnalyzer; bundle audit may not be installed, or property \"analyzer.bundle.audit.path\" may not be set.", e);
        }
    }

    /**
     * Test when Ruby bundle-audit is not available on the system.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testInvalidBundleAudit() throws AnalysisException, DatabaseException {

        String path = BaseTest.getResourceAsFile(this, "ruby/invalid-bundle-audit").getAbsolutePath();
        getSettings().setString(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_PATH, path);
        analyzer.initialize(getSettings());
        try {
            //initialize should fail.
            analyzer.prepare(null);
        } catch (InitializationException e) {
            //expected, so ignore.
            assertNotNull(e);
        } finally {
            assertThat("`invalid-bundle-audit` is not a valid executable. Ruby Bundle Audit Analyzer is disabled as expected.",
                    analyzer.isEnabled(), is(false));
        }
    }

    /**
     * Test Ruby dependencies and their paths.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     * @throws DatabaseException thrown when an exception occurs
     */
    @Test
    public void testDependenciesPath() throws AnalysisException, DatabaseException {
        try (Engine engine = new Engine(getSettings())) {
            try {
                engine.scan(BaseTest.getResourceAsFile(this, "ruby/vulnerable/gems/rails-4.1.15/"));
                engine.analyzeDependencies();
            } catch (NullPointerException ex) {
                LOGGER.error("NPE", ex);
                fail(ex.getMessage());
            } catch (ExceptionCollection ex) {
                Assume.assumeNoException("Exception setting up RubyBundleAuditAnalyzer; bundle audit may not be installed, or property \"analyzer.bundle.audit.path\" may not be set.", ex);
                return;
            }
            Dependency[] dependencies = engine.getDependencies();
            LOGGER.info("{} dependencies found.", dependencies.length);
        }
    }
}
