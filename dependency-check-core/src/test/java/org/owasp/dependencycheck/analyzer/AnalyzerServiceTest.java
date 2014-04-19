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

import java.util.Iterator;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class AnalyzerServiceTest extends BaseTest {

    /**
     * Test of getAnalyzers method, of class AnalyzerService.
     */
    @Test
    public void testGetAnalyzers() {
        AnalyzerService instance = new AnalyzerService();
        Iterator<Analyzer> result = instance.getAnalyzers();

        boolean found = false;
        while (result.hasNext()) {
            Analyzer a = result.next();
            if ("Jar Analyzer".equals(a.getName())) {
                found = true;
            }
        }
        assertTrue("JarAnalyzer loaded", found);
    }
}
