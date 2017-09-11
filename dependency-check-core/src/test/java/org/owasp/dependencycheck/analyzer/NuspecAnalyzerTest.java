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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

import java.io.File;

public class NuspecAnalyzerTest extends BaseTest {

    private NuspecAnalyzer instance;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        instance = new NuspecAnalyzer();
        instance.initialize(getSettings());
        instance.prepare(null);
        instance.setEnabled(true);
    }

    @Test
    public void testGetAnalyzerName() {
        assertEquals("Nuspec Analyzer", instance.getName());
    }

    @Test
    public void testSupportsFileExtensions() {
        assertTrue(instance.accept(new File("test.nuspec")));
        assertFalse(instance.accept(new File("test.nupkg")));
    }

    @Test
    public void testGetAnalysisPhaze() {
        assertEquals(AnalysisPhase.INFORMATION_COLLECTION, instance.getAnalysisPhase());
    }
}
