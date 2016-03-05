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

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;

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
        try {
            analyzer = new RubyBundleAuditAnalyzer();
            analyzer.setFilesMatched(true);
            analyzer.initialize();
        } catch (Exception e) {
            //LOGGER.warn("Exception setting up RubyBundleAuditAnalyzer. Tests will be incomplete", e);
            Assume.assumeNoException("Exception setting up RubyBundleAuditAnalyzer; bundle audit may not be installed. Tests will be incomplete", e);
        }
    }

    /**
     * Cleanup the analyzer's temp files, etc.
     *
     * @throws Exception thrown if there is a problem
     */
    @After
    public void tearDown() throws Exception {
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
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "ruby/vulnerable/Gemfile.lock"));
        final Engine engine = new Engine();
        analyzer.analyze(result, engine);
        assertThat(engine.getDependencies().size(), is(not(0)));
    }
}
