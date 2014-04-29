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

import org.junit.Before;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.analyzer.exception.AnalysisException;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.suppression.SuppressionParseException;
import org.owasp.dependencycheck.suppression.SuppressionRule;
import org.owasp.dependencycheck.utils.Settings;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class AbstractSuppressionAnalyzerTest extends BaseTest {

    private AbstractSuppressionAnalyzer instance;

    @Before
    public void createObjectUnderTest() throws Exception {
        instance = new AbstractSuppressionAnalyzerImpl();
    }

    /**
     * Test of getSupportedExtensions method, of class AbstractSuppressionAnalyzer.
     */
    @Test
    public void testGetSupportedExtensions() {
        Set<String> result = instance.getSupportedExtensions();
        assertNull(result);
    }

    /**
     * Test of getRules method, of class AbstractSuppressionAnalyzer for suppression file declared as URL.
     */
    @Test
    public void testGetRulesFromSuppressionFileFromURL() throws Exception {
        setSupressionFileFromURL();
        instance.initialize();
        int expCount = 5;
        List<SuppressionRule> result = instance.getRules();
        assertEquals(expCount, result.size());
    }

    /**
     * Test of getRules method, of class AbstractSuppressionAnalyzer for suppression file declared as URL.
     */
    @Test
    public void testGetRulesFromSuppressionFileInClasspath() throws Exception {
        Settings.setString(Settings.KEYS.SUPPRESSION_FILE, "suppressions.xml");
        instance.initialize();
        int expCount = 5;
        List<SuppressionRule> result = instance.getRules();
        assertEquals(expCount, result.size());
    }

    @Test(expected = SuppressionParseException.class)
    public void testFailureToLocateSuppressionFileAnywhere() throws Exception {
        Settings.setString(Settings.KEYS.SUPPRESSION_FILE, "doesnotexist.xml");
        instance.initialize();
    }

    private void setSupressionFileFromURL() throws Exception {
        try {
            final String uri = this.getClass().getClassLoader().getResource("suppressions.xml").toURI().toURL().toString();
            Settings.setString(Settings.KEYS.SUPPRESSION_FILE, uri);
        } catch (URISyntaxException ex) {
            Logger.getLogger(AbstractSuppressionAnalyzerTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (MalformedURLException ex) {
            Logger.getLogger(AbstractSuppressionAnalyzerTest.class.getName()).log(Level.SEVERE, null, ex);
        }
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
