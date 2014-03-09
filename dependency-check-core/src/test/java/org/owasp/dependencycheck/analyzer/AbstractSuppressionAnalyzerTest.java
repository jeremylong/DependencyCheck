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

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.suppression.SuppressionRule;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class AbstractSuppressionAnalyzerTest {

    public AbstractSuppressionAnalyzerTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
        try {
            final String uri = this.getClass().getClassLoader().getResource("suppressions.xml").toURI().toURL().toString();
            Settings.setString(Settings.KEYS.SUPPRESSION_FILE, uri);
        } catch (URISyntaxException ex) {
            Logger.getLogger(AbstractSuppressionAnalyzerTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (MalformedURLException ex) {
            Logger.getLogger(AbstractSuppressionAnalyzerTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getSupportedExtensions method, of class AbstractSuppressionAnalyzer.
     */
    @Test
    public void testGetSupportedExtensions() {
        AbstractSuppressionAnalyzer instance = new AbstractSuppressionAnalyzerImpl();
        Set<String> result = instance.getSupportedExtensions();
        assertNull(result);
    }

    /**
     * Test of supportsExtension method, of class AbstractSuppressionAnalyzer.
     */
    @Test
    public void testSupportsExtension() {
        String extension = "jar";
        AbstractSuppressionAnalyzer instance = new AbstractSuppressionAnalyzerImpl();
        boolean expResult = true;
        boolean result = instance.supportsExtension(extension);
        assertEquals(expResult, result);
    }

    /**
     * Test of initialize method, of class AbstractSuppressionAnalyzer.
     */
    @Test
    public void testInitialize() throws Exception {
        AbstractSuppressionAnalyzer instance = new AbstractSuppressionAnalyzerImpl();
        instance.initialize();
    }

    /**
     * Test of getRules method, of class AbstractSuppressionAnalyzer.
     */
    @Test
    public void testGetRules() throws Exception {
        AbstractSuppressionAnalyzer instance = new AbstractSuppressionAnalyzerImpl();
        instance.initialize();
        int expCount = 5;
        List<SuppressionRule> result = instance.getRules();
        assertEquals(expCount, result.size());
    }

    public class AbstractSuppressionAnalyzerImpl extends AbstractSuppressionAnalyzer {

        @Override
        public void analyze(Dependency dependency, Engine engine) throws AnalysisException {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public String getName() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }

        @Override
        public AnalysisPhase getAnalysisPhase() {
            throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        }
    }

}
