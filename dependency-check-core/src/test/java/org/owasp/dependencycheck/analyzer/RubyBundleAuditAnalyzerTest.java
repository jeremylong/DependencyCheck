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

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Unit tests for {@link RubyBundleAuditAnalyzer}.
 *
 * @author Dale Visser
 */
public class RubyBundleAuditAnalyzerTest extends BaseTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(RubyBundleAuditAnalyzerTest.class);

    /**
     * The analyzer to test.
     */
    RubyBundleAuditAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    public void setUp() throws Exception {
    	Settings.initialize();
        analyzer = new RubyBundleAuditAnalyzer();
        analyzer.setFilesMatched(true);
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    public void tearDown() throws Exception {
    	Settings.cleanup();
        analyzer.close();
        analyzer = null;
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
    	try {
            analyzer.initialize();

            final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                    "ruby/vulnerable/gems/rails-4.1.15/Gemfile.lock"));
            final Engine engine = new Engine();
            analyzer.analyze(result, engine);
            int size = engine.getDependencies().size();
            assertThat(size, is(1));
            
            Dependency dependency = engine.getDependencies().get(0);
            assertTrue(dependency.getProductEvidence().toString().toLowerCase().contains("redcarpet"));
            assertTrue(dependency.getVersionEvidence().toString().toLowerCase().contains("2.2.2"));
            
        } catch (Exception e) {
            LOGGER.warn("Exception setting up RubyBundleAuditAnalyzer. Make sure Ruby gem bundle-audit is installed. You may also need to set property \"analyzer.bundle.audit.path\".", e);
            Assume.assumeNoException("Exception setting up RubyBundleAuditAnalyzer; bundle audit may not be installed, or property \"analyzer.bundle.audit.path\" may not be set.", e);
        }
    }

    /**
     * Test when Ruby bundle-audit is not available on the system.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testMissingBundleAudit() throws AnalysisException, DatabaseException {
    	//set a non-exist bundle-audit
        Settings.setString(Settings.KEYS.ANALYZER_BUNDLE_AUDIT_PATH, "phantom-bundle-audit");
        try {
            //initialize should fail.
			analyzer.initialize();
		} catch (Exception e) {
			//expected, so ignore.
		}
        finally {
	        assertThat(analyzer.isEnabled(), is(false));
			LOGGER.info("phantom-bundle-audit is not available. Ruby Bundle Audit Analyzer is disabled as expected.");
        }
    }
}
