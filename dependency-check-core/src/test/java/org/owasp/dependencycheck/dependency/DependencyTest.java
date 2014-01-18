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
package org.owasp.dependencycheck.dependency;

import java.io.File;
import java.util.List;
import java.util.Set;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DependencyTest {

    public DependencyTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getFileName method, of class Dependency.
     */
    @Test
    public void testGetFileName() {
        Dependency instance = new Dependency();
        String expResult = "filename";
        instance.setFileName(expResult);
        String result = instance.getFileName();
        assertEquals(expResult, result);
    }

    /**
     * Test of setFileName method, of class Dependency.
     */
    @Test
    public void testSetFileName() {
        String fileName = "test.file";
        Dependency instance = new Dependency();
        instance.setFileName(fileName);
        assertEquals(fileName, instance.getFileName());
    }

    /**
     * Test of setActualFilePath method, of class Dependency.
     */
    @Test
    public void testSetActualFilePath() {
        String actualFilePath = "test.file";
        Dependency instance = new Dependency();
        instance.setActualFilePath(actualFilePath);
        assertEquals(actualFilePath, instance.getActualFilePath());
    }

    /**
     * Test of getActualFilePath method, of class Dependency.
     */
    @Test
    public void testGetActualFilePath() {
        Dependency instance = new Dependency();
        String expResult = "test.file";
        instance.setActualFilePath(expResult);
        String result = instance.getActualFilePath();
        assertEquals(expResult, result);
    }

    /**
     * Test of setFilePath method, of class Dependency.
     */
    @Test
    public void testSetFilePath() {
        String filePath = "test.file";
        Dependency instance = new Dependency();
        instance.setFilePath(filePath);
        assertEquals(filePath, instance.getFilePath());
    }

    /**
     * Test of getFilePath method, of class Dependency.
     */
    @Test
    public void testGetFilePath() {
        Dependency instance = new Dependency();
        String expResult = "path/test.file";
        instance.setFilePath(expResult);
        String result = instance.getFilePath();
        assertEquals(expResult, result);
    }

    /**
     * Test of setFileExtension method, of class Dependency.
     */
    @Test
    public void testSetFileExtension() {
        String fileExtension = "jar";
        Dependency instance = new Dependency();
        instance.setFileExtension(fileExtension);
        assertEquals(fileExtension, instance.getFileExtension());
    }

    /**
     * Test of getFileExtension method, of class Dependency.
     */
    @Test
    public void testGetFileExtension() {
        Dependency instance = new Dependency();
        String expResult = "jar";
        instance.setFileExtension(expResult);
        String result = instance.getFileExtension();
        assertEquals(expResult, result);
    }

    /**
     * Test of getMd5sum method, of class Dependency.
     */
    @Test
    public void testGetMd5sum() {
        File file = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        Dependency instance = new Dependency(file);
//        assertEquals("89CE9E36AA9A9E03F1450936D2F4F8DD0F961F8B", result.getSha1sum());
        String expResult = "C30B57142E1CCBC1EFD5CD15F307358F";
        String result = instance.getMd5sum();
        assertEquals(expResult, result);
    }

    /**
     * Test of setMd5sum method, of class Dependency.
     */
    @Test
    public void testSetMd5sum() {
        String md5sum = "test";
        Dependency instance = new Dependency();
        instance.setMd5sum(md5sum);
        assertEquals(md5sum, instance.getMd5sum());
    }

    /**
     * Test of getSha1sum method, of class Dependency.
     */
    @Test
    public void testGetSha1sum() {
        File file = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
        Dependency instance = new Dependency(file);
        String expResult = "89CE9E36AA9A9E03F1450936D2F4F8DD0F961F8B";
        String result = instance.getSha1sum();
        assertEquals(expResult, result);
    }

    /**
     * Test of setSha1sum method, of class Dependency.
     */
    @Test
    public void testSetSha1sum() {
        String sha1sum = "test";
        Dependency instance = new Dependency();
        instance.setSha1sum(sha1sum);
        assertEquals(sha1sum, instance.getSha1sum());
    }

    /**
     * Test of getIdentifiers method, of class Dependency.
     */
    @Test
    public void testGetIdentifiers() {
        Dependency instance = new Dependency();
        List expResult = null;
        Set<Identifier> result = instance.getIdentifiers();

        assertTrue(true); //this is just a getter setter pair.
    }

    /**
     * Test of setIdentifiers method, of class Dependency.
     */
    @Test
    public void testSetIdentifiers() {
        Set<Identifier> identifiers = null;
        Dependency instance = new Dependency();
        instance.setIdentifiers(identifiers);
        assertTrue(true); //this is just a getter setter pair.
    }

    /**
     * Test of addIdentifier method, of class Dependency.
     */
    @Test
    public void testAddIdentifier() {
        String type = "cpe";
        String value = "cpe:/a:apache:struts:2.1.2";
        String url = "http://somewhere";
        Identifier expResult = new Identifier(type, value, url);

        Dependency instance = new Dependency();
        instance.addIdentifier(type, value, url);
        assertEquals(1, instance.getIdentifiers().size());
        assertTrue("Identifier doesn't contain expected result.", instance.getIdentifiers().contains(expResult));
    }

    /**
     * Test of getEvidence method, of class Dependency.
     */
    @Test
    public void testGetEvidence() {
        Dependency instance = new Dependency();
        EvidenceCollection expResult = null;
        EvidenceCollection result = instance.getEvidence();
        assertTrue(true); //this is just a getter setter pair.
    }

    /**
     * Test of getEvidenceUsed method, of class Dependency.
     */
    @Test
    public void testGetEvidenceUsed() {
        Dependency instance = new Dependency();
        String expResult = "used";

        instance.getProductEvidence().addEvidence("used", "used", "used", Confidence.HIGH);
        instance.getProductEvidence().addEvidence("not", "not", "not", Confidence.MEDIUM);
        for (Evidence e : instance.getProductEvidence().iterator(Confidence.HIGH)) {
            String use = e.getValue();
        }

        EvidenceCollection result = instance.getEvidenceUsed();

        assertEquals(1, result.size());
        assertTrue(result.containsUsedString(expResult));
    }

    /**
     * Test of getVendorEvidence method, of class Dependency.
     */
    @Test
    public void testGetVendorEvidence() {
        Dependency instance = new Dependency();
        EvidenceCollection expResult = null;
        EvidenceCollection result = instance.getVendorEvidence();
        assertTrue(true); //this is just a getter setter pair.
    }

    /**
     * Test of getProductEvidence method, of class Dependency.
     */
    @Test
    public void testGetProductEvidence() {
        Dependency instance = new Dependency();
        EvidenceCollection expResult = null;
        EvidenceCollection result = instance.getProductEvidence();
        assertTrue(true); //this is just a getter setter pair.
    }

    /**
     * Test of getVersionEvidence method, of class Dependency.
     */
    @Test
    public void testGetVersionEvidence() {
        Dependency instance = new Dependency();
        EvidenceCollection expResult = null;
        EvidenceCollection result = instance.getVersionEvidence();
        assertTrue(true); //this is just a getter setter pair.
    }
}
