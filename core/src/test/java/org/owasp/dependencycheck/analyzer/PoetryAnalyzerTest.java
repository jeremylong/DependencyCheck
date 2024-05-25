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
 * Copyright (c) 2019 Nima Yahyazadeh. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.File;

import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;

public class PoetryAnalyzerTest extends BaseTest {

    private PoetryAnalyzer analyzer;
    private Engine engine;

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        analyzer = new PoetryAnalyzer();
        engine = new Engine(this.getSettings());
    }

    @Test
    public void testName() {
        assertEquals("Analyzer name wrong.", "Poetry Analyzer",
                analyzer.getName());
    }

    @Test
    public void testSupportsFiles() {
        assertThat(analyzer.accept(new File("poetry.lock")), is(true));
    }

    @Test
    public void testPoetryLock() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "poetry.lock"));
        analyzer.analyze(result, engine);
        assertEquals(88, engine.getDependencies().length);
        boolean found = false;
        for (Dependency d : engine.getDependencies()) {
            if ("urllib3".equals(d.getName())) {
                found = true;
                assertEquals("1.26.12", d.getVersion());
                assertThat(d.getDisplayFileName(), equalTo("urllib3:1.26.12"));
                assertEquals(PythonDistributionAnalyzer.DEPENDENCY_ECOSYSTEM, d.getEcosystem());
            }
        }
        assertTrue("Expeced to find PyYAML", found);
    }

    @Test
    public void testPyprojectToml() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "python-myproject-toml/pyproject.toml"));
        //returns with no error.
        analyzer.analyze(result, engine);
    }

    @Test(expected = AnalysisException.class)
    public void testPoetryToml() throws AnalysisException {
        final Dependency result = new Dependency(BaseTest.getResourceAsFile(this, "python-poetry-toml/pyproject.toml"));
        //causes an exception.
        analyzer.analyze(result, engine);
    }
}
