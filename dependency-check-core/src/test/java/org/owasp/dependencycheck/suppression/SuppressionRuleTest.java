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
package org.owasp.dependencycheck.suppression;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Vulnerability;

/**
 * Test of the suppression rule.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class SuppressionRuleTest {

    public SuppressionRuleTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    //<editor-fold defaultstate="collapsed" desc="Stupid tests of properties">
    /**
     * Test of FilePath property, of class SuppressionRule.
     */
    @Test
    public void testFilePath() {
        SuppressionRule instance = new SuppressionRule();
        PropertyType expResult = new PropertyType();
        expResult.setValue("test");
        instance.setFilePath(expResult);
        PropertyType result = instance.getFilePath();
        assertEquals(expResult, result);
    }

    /**
     * Test of Sha1 property, of class SuppressionRule.
     */
    @Test
    public void testSha1() {
        SuppressionRule instance = new SuppressionRule();
        String expResult = "384FAA82E193D4E4B0546059CA09572654BC3970";
        instance.setSha1(expResult);
        String result = instance.getSha1();
        assertEquals(expResult, result);
    }

    /**
     * Test of Cpe property, of class SuppressionRule.
     */
    @Test
    public void testCpe() {
        SuppressionRule instance = new SuppressionRule();
        ArrayList<PropertyType> cpe = new ArrayList<PropertyType>();
        instance.setCpe(cpe);
        assertFalse(instance.hasCpe());
        PropertyType pt = new PropertyType();
        pt.setValue("one");
        instance.addCpe(pt);
        assertTrue(instance.hasCpe());
        List<PropertyType> result = instance.getCpe();
        assertEquals(cpe, result);

    }

    /**
     * Test of CvssBelow property, of class SuppressionRule.
     */
    @Test
    public void testGetCvssBelow() {
        SuppressionRule instance = new SuppressionRule();
        ArrayList<Float> cvss = new ArrayList<Float>();
        instance.setCvssBelow(cvss);
        assertFalse(instance.hasCvssBelow());
        instance.addCvssBelow(0.7f);
        assertTrue(instance.hasCvssBelow());
        List<Float> result = instance.getCvssBelow();
        assertEquals(cvss, result);
    }

    /**
     * Test of Cwe property, of class SuppressionRule.
     */
    @Test
    public void testCwe() {
        SuppressionRule instance = new SuppressionRule();
        ArrayList<String> cwe = new ArrayList<String>();
        instance.setCwe(cwe);
        assertFalse(instance.hasCwe());
        instance.addCwe("2");
        assertTrue(instance.hasCwe());
        List<String> result = instance.getCwe();
        assertEquals(cwe, result);
    }

    /**
     * Test of Cve property, of class SuppressionRule.
     */
    @Test
    public void testCve() {
        SuppressionRule instance = new SuppressionRule();
        ArrayList<String> cve = new ArrayList<String>();
        instance.setCve(cve);
        assertFalse(instance.hasCve());
        instance.addCve("CVE-2013-1337");
        assertTrue(instance.hasCve());
        List<String> result = instance.getCve();
        assertEquals(cve, result);
    }
    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="Ignored duplicate tests, left in, as empty tests, so IDE doesn't re-generate them">
    /**
     * Test of getFilePath method, of class SuppressionRule.
     */
    @Test
    public void testGetFilePath() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of setFilePath method, of class SuppressionRule.
     */
    @Test
    public void testSetFilePath() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of getSha1 method, of class SuppressionRule.
     */
    @Test
    public void testGetSha1() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of setSha1 method, of class SuppressionRule.
     */
    @Test
    public void testSetSha1() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of getCpe method, of class SuppressionRule.
     */
    @Test
    public void testGetCpe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of setCpe method, of class SuppressionRule.
     */
    @Test
    public void testSetCpe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of addCpe method, of class SuppressionRule.
     */
    @Test
    public void testAddCpe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of hasCpe method, of class SuppressionRule.
     */
    @Test
    public void testHasCpe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of setCvssBelow method, of class SuppressionRule.
     */
    @Test
    public void testSetCvssBelow() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of addCvssBelow method, of class SuppressionRule.
     */
    @Test
    public void testAddCvssBelow() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of hasCvssBelow method, of class SuppressionRule.
     */
    @Test
    public void testHasCvssBelow() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of getCwe method, of class SuppressionRule.
     */
    @Test
    public void testGetCwe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of setCwe method, of class SuppressionRule.
     */
    @Test
    public void testSetCwe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of addCwe method, of class SuppressionRule.
     */
    @Test
    public void testAddCwe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of hasCwe method, of class SuppressionRule.
     */
    @Test
    public void testHasCwe() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of getCve method, of class SuppressionRule.
     */
    @Test
    public void testGetCve() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of setCve method, of class SuppressionRule.
     */
    @Test
    public void testSetCve() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of addCve method, of class SuppressionRule.
     */
    @Test
    public void testAddCve() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }

    /**
     * Test of hasCve method, of class SuppressionRule.
     */
    @Test
    public void testHasCve() {
        //already tested, this is just left so the IDE doesn't recreate it.
    }
    //</editor-fold>

    /**
     * Test of cpeHasNoVersion method, of class SuppressionRule.
     */
    @Test
    public void testCpeHasNoVersion() {
        PropertyType c = new PropertyType();
        c.setValue("cpe:/a:microsoft:.net_framework:4.5");
        SuppressionRule instance = new SuppressionRule();
        assertFalse(instance.cpeHasNoVersion(c));
        c.setValue("cpe:/a:microsoft:.net_framework:");
        assertFalse(instance.cpeHasNoVersion(c));
        c.setValue("cpe:/a:microsoft:.net_framework");
        assertTrue(instance.cpeHasNoVersion(c));
    }

    /**
     * Test of countCharacter method, of class SuppressionRule.
     */
    @Test
    public void testCountCharacter() {
        String str = "cpe:/a:microsoft:.net_framework:4.5";
        char c = ':';
        SuppressionRule instance = new SuppressionRule();
        int expResult = 4;
        int result = instance.countCharacter(str, c);
        assertEquals(expResult, result);
        str = "::";
        expResult = 2;
        result = instance.countCharacter(str, c);
        assertEquals(expResult, result);
        str = "these are not the characters you are looking for";
        expResult = 0;
        result = instance.countCharacter(str, c);
        assertEquals(expResult, result);
    }

    /**
     * Test of cpeMatches method, of class SuppressionRule.
     */
    @Test
    public void testCpeMatches() {
        Identifier identifier = new Identifier("cwe", "cpe:/a:microsoft:.net_framework:4.5", "some url not needed for this test");

        PropertyType cpe = new PropertyType();
        cpe.setValue("cpe:/a:microsoft:.net_framework:4.5");

        SuppressionRule instance = new SuppressionRule();
        boolean expResult = true;
        boolean result = instance.cpeMatches(cpe, identifier);
        assertEquals(expResult, result);

        cpe.setValue("cpe:/a:microsoft:.net_framework:4.0");
        expResult = false;
        result = instance.cpeMatches(cpe, identifier);
        assertEquals(expResult, result);

        cpe.setValue("CPE:/a:microsoft:.net_framework:4.5");
        cpe.setCaseSensitive(true);
        expResult = false;
        result = instance.cpeMatches(cpe, identifier);
        assertEquals(expResult, result);

        cpe.setValue("cpe:/a:microsoft:.net_framework");
        cpe.setCaseSensitive(false);
        expResult = true;
        result = instance.cpeMatches(cpe, identifier);
        assertEquals(expResult, result);

        cpe.setValue("cpe:/a:microsoft:.*");
        cpe.setRegex(true);
        expResult = true;
        result = instance.cpeMatches(cpe, identifier);
        assertEquals(expResult, result);

        cpe.setValue("CPE:/a:microsoft:.*");
        cpe.setRegex(true);
        cpe.setCaseSensitive(true);
        expResult = false;
        result = instance.cpeMatches(cpe, identifier);
        assertEquals(expResult, result);

        cpe.setValue("cpe:/a:apache:.*");
        cpe.setRegex(true);
        cpe.setCaseSensitive(false);
        expResult = false;
        result = instance.cpeMatches(cpe, identifier);
        assertEquals(expResult, result);
    }

    /**
     * Test of process method, of class SuppressionRule.
     */
    @Test
    public void testProcess() {
        File struts = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        Dependency dependency = new Dependency(struts);
        dependency.addIdentifier("cwe", "cpe:/a:microsoft:.net_framework:4.5", "some url not needed for this test");
        String sha1 = dependency.getSha1sum();
        dependency.setSha1sum("384FAA82E193D4E4B0546059CA09572654BC3970");
        Vulnerability v = createVulnerability();
        dependency.addVulnerability(v);

        //cwe
        SuppressionRule instance = new SuppressionRule();
        instance.setSha1(sha1);
        instance.addCwe("287");
        instance.process(dependency);
        assertTrue(dependency.getVulnerabilities().size() == 1);
        dependency.setSha1sum(sha1);
        instance.process(dependency);
        assertTrue(dependency.getVulnerabilities().isEmpty());
        assertTrue(dependency.getSuppressedVulnerabilities().size() == 1);

        //cvss
        dependency.addVulnerability(v);
        instance = new SuppressionRule();
        instance.addCvssBelow(5f);
        instance.process(dependency);
        assertTrue(dependency.getVulnerabilities().size() == 1);
        instance.addCvssBelow(8f);
        instance.process(dependency);
        assertTrue(dependency.getVulnerabilities().isEmpty());
        assertTrue(dependency.getSuppressedVulnerabilities().size() == 1);

        //cve
        dependency.addVulnerability(v);
        instance = new SuppressionRule();
        instance.addCve("CVE-2012-1337");
        instance.process(dependency);
        assertTrue(dependency.getVulnerabilities().size() == 1);
        instance.addCve("CVE-2013-1337");
        instance.process(dependency);
        assertTrue(dependency.getVulnerabilities().isEmpty());
        assertTrue(dependency.getSuppressedVulnerabilities().size() == 1);

        //cpe
        instance = new SuppressionRule();
        PropertyType pt = new PropertyType();
        pt.setValue("cpe:/a:microsoft:.net_framework:4.0");
        instance.addCpe(pt);
        instance.process(dependency);
        assertTrue(dependency.getIdentifiers().size() == 1);
        pt = new PropertyType();
        pt.setValue("cpe:/a:microsoft:.net_framework:4.5");
        instance.addCpe(pt);
        pt = new PropertyType();
        pt.setValue(".*");
        pt.setRegex(true);
        instance.setFilePath(pt);
        instance.process(dependency);
        assertTrue(dependency.getIdentifiers().isEmpty());
        assertTrue(dependency.getSuppressedIdentifiers().size() == 1);

        dependency.addIdentifier("cwe", "cpe:/a:microsoft:.net_framework:4.0", "some url not needed for this test");
        dependency.addIdentifier("cwe", "cpe:/a:microsoft:.net_framework:4.5", "some url not needed for this test");
        dependency.addIdentifier("cwe", "cpe:/a:microsoft:.net_framework:5.0", "some url not needed for this test");
        pt = new PropertyType();
        pt.setValue("cpe:/a:microsoft:.net_framework");
        instance.addCpe(pt);
        assertTrue(dependency.getIdentifiers().size() == 3);
        instance.process(dependency);
        assertTrue(dependency.getIdentifiers().isEmpty());
        assertTrue(dependency.getSuppressedIdentifiers().size() == 3);
    }

    private Vulnerability createVulnerability() {
        Vulnerability v = new Vulnerability();
        v.setCwe("CWE-287 Improper Authentication");
        v.setName("CVE-2013-1337");
        v.setCvssScore(7.5f);
        return v;
    }
}
