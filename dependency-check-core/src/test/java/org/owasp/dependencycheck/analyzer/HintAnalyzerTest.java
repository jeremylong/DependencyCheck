/*
 * Copyright 2014 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.analyzer;

import java.io.File;
import java.util.Set;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Evidence;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class HintAnalyzerTest extends BaseTest {

    @Before
    public void setUp() throws Exception {
        org.owasp.dependencycheck.data.nvdcve.BaseDBTestCase.ensureDBExists();
    }

    /**
     * Test of getName method, of class HintAnalyzer.
     */
    @Test
    public void testGetName() {
        HintAnalyzer instance = new HintAnalyzer();
        String expResult = "Hint Analyzer";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of getAnalysisPhase method, of class HintAnalyzer.
     */
    @Test
    public void testGetAnalysisPhase() {
        HintAnalyzer instance = new HintAnalyzer();
        AnalysisPhase expResult = AnalysisPhase.PRE_IDENTIFIER_ANALYSIS;
        AnalysisPhase result = instance.getAnalysisPhase();
        assertEquals(expResult, result);
    }

    /**
     * Test of analyze method, of class HintAnalyzer.
     */
    @Test
    public void testAnalyze() throws Exception {
        HintAnalyzer instance = new HintAnalyzer();

        File guice = new File(this.getClass().getClassLoader().getResource("guice-3.0.jar").getPath());
        //Dependency guice = new Dependency(fileg);
        File spring = new File(this.getClass().getClassLoader().getResource("spring-core-3.0.0.RELEASE.jar").getPath());
        //Dependency spring = new Dependency(files);
        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        Settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        Engine engine = new Engine();

        engine.scan(guice);
        engine.scan(spring);
        engine.analyzeDependencies();
        Dependency gdep = null;
        Dependency sdep = null;
        for (Dependency d : engine.getDependencies()) {
            if (d.getActualFile().equals(guice)) {
                gdep = d;
            } else {
                sdep = d;
            }
        }
        final Evidence springTest1 = new Evidence("hint analyzer", "product", "springsource_spring_framework", Confidence.HIGH);
        final Evidence springTest2 = new Evidence("hint analyzer", "vendor", "SpringSource", Confidence.HIGH);
        final Evidence springTest3 = new Evidence("hint analyzer", "vendor", "vmware", Confidence.HIGH);
        final Evidence springTest4 = new Evidence("hint analyzer", "product", "springsource_spring_framework", Confidence.HIGH);
        final Evidence springTest5 = new Evidence("hint analyzer", "vendor", "vmware", Confidence.HIGH);

        Set<Evidence> evidence = gdep.getEvidence().getEvidence();
        assertFalse(evidence.contains(springTest1));
        assertFalse(evidence.contains(springTest2));
        assertFalse(evidence.contains(springTest3));
        assertFalse(evidence.contains(springTest4));
        assertFalse(evidence.contains(springTest5));

        evidence = sdep.getEvidence().getEvidence();
        assertTrue(evidence.contains(springTest1));
        assertTrue(evidence.contains(springTest2));
        assertTrue(evidence.contains(springTest3));
        //assertTrue(evidence.contains(springTest4));
        //assertTrue(evidence.contains(springTest5));

    }

}
