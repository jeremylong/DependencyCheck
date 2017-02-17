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
 * Copyright (c) 2016 Bianca Jiang. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

/**
 * Unit tests for {@link RubyBundlerAnalyzer}.
 *
 * @author Bianca Jiang
 */
public class RubyBundlerAnalyzerTest extends BaseTest {

    /**
     * The analyzer to test.
     */
    private RubyBundlerAnalyzer analyzer;

    /**
     * Correctly setup the analyzer for testing.
     *
     * @throws Exception thrown if there is a problem
     */
    @Before
    public void setUp() throws Exception {
        analyzer = new RubyBundlerAnalyzer();
        analyzer.setFilesMatched(true);
        analyzer.initialize();
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
     * Test Analyzer name.
     */
    @Test
    public void testGetName() {
        assertThat(analyzer.getName(), is("Ruby Bundler Analyzer"));
    }

    /**
     * Test Ruby Gemspec file support.
     */
    @Test
    public void testSupportsFiles() {
        assertThat(analyzer.accept(new File("test.gemspec")), is(false));
        assertThat(analyzer.accept(new File("specifications" + File.separator + "test.gemspec")), is(true));
    }

    /**
     * Test Ruby Bundler created gemspec analysis.
     *
     * @throws AnalysisException is thrown when an exception occurs.
     */
    @Test
    public void testAnalyzeGemspec() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this,
                "ruby/vulnerable/gems/rails-4.1.15/vendor/bundle/ruby/2.2.0/specifications/dalli-2.7.5.gemspec"));
        analyzer.analyze(result, null);
        
        final String vendorString = result.getVendorEvidence().toString();
        assertThat(vendorString, containsString("Peter M. Goldstein"));
        assertThat(vendorString, containsString("Mike Perham"));
        assertThat(vendorString, containsString("peter.m.goldstein@gmail.com"));
        assertThat(vendorString, containsString("https://github.com/petergoldstein/dalli"));
        assertThat(vendorString, containsString("MIT"));
        assertThat(result.getProductEvidence().toString(), containsString("dalli"));
        assertThat(result.getProductEvidence().toString(), containsString("High performance memcached client for Ruby"));
        assertThat(result.getVersionEvidence().toString(), containsString("2.7.5"));
    }
}
