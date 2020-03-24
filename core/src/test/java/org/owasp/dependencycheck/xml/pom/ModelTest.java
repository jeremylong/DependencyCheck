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
 * Copyright (c) 2015 The OWASP Foundatio. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.pom;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.BaseTest;

/**
 *
 * @author jeremy long
 */
public class ModelTest extends BaseTest {

    /**
     * Test of getName method, of class Model.
     */
    @Test
    public void testGetName() {
        Model instance = new Model();
        instance.setName("");
        String expResult = "";
        String result = instance.getName();
        assertEquals(expResult, result);
    }

    /**
     * Test of setName method, of class Model.
     */
    @Test
    public void testSetName() {
        String name = "name";
        Model instance = new Model();
        instance.setName(name);
        assertEquals("name", instance.getName());
    }

    /**
     * Test of getOrganization method, of class Model.
     */
    @Test
    public void testGetOrganization() {
        Model instance = new Model();
        instance.setOrganization("");
        String expResult = "";
        String result = instance.getOrganization();
        assertEquals(expResult, result);
    }

    /**
     * Test of setOrganization method, of class Model.
     */
    @Test
    public void testSetOrganization() {
        String organization = "apache";
        Model instance = new Model();
        instance.setOrganization(organization);
        assertEquals("apache", instance.getOrganization());
    }

    /**
     * Test of getDescription method, of class Model.
     */
    @Test
    public void testGetDescription() {
        Model instance = new Model();
        instance.setDescription("");
        String expResult = "";
        String result = instance.getDescription();
        assertEquals(expResult, result);
    }

    /**
     * Test of setDescription method, of class Model.
     */
    @Test
    public void testSetDescription() {
        String description = "description";
        String expected = "description";
        Model instance = new Model();
        instance.setDescription(description);
        assertEquals(expected, instance.getDescription());
    }

    /**
     * Test of getGroupId method, of class Model.
     */
    @Test
    public void testGetGroupId() {
        Model instance = new Model();
        instance.setGroupId("");
        String expResult = "";
        String result = instance.getGroupId();
        assertEquals(expResult, result);
    }

    /**
     * Test of setGroupId method, of class Model.
     */
    @Test
    public void testSetGroupId() {
        String groupId = "aaa";
        String expected = "aaa";
        Model instance = new Model();
        instance.setGroupId(groupId);
        assertEquals(expected, instance.getGroupId());
    }

    /**
     * Test of getArtifactId method, of class Model.
     */
    @Test
    public void testGetArtifactId() {
        Model instance = new Model();
        instance.setArtifactId("");
        String expResult = "";
        String result = instance.getArtifactId();
        assertEquals(expResult, result);
    }

    /**
     * Test of setArtifactId method, of class Model.
     */
    @Test
    public void testSetArtifactId() {
        String artifactId = "aaa";
        String expected = "aaa";
        Model instance = new Model();
        instance.setArtifactId(artifactId);
        assertEquals(expected, instance.getArtifactId());
    }

    /**
     * Test of getVersion method, of class Model.
     */
    @Test
    public void testGetVersion() {
        Model instance = new Model();
        instance.setVersion("");
        String expResult = "";
        String result = instance.getVersion();
        assertEquals(expResult, result);
    }

    /**
     * Test of setVersion method, of class Model.
     */
    @Test
    public void testSetVersion() {
        String version = "";
        Model instance = new Model();
        instance.setVersion(version);
        assertNotNull(instance.getVersion());
    }

    /**
     * Test of getParentGroupId method, of class Model.
     */
    @Test
    public void testGetParentGroupId() {
        Model instance = new Model();
        instance.setParentGroupId("");
        String expResult = "";
        String result = instance.getParentGroupId();
        assertEquals(expResult, result);
    }

    /**
     * Test of setParentGroupId method, of class Model.
     */
    @Test
    public void testSetParentGroupId() {
        String parentGroupId = "org.owasp";
        Model instance = new Model();
        instance.setParentGroupId(parentGroupId);
        assertEquals("org.owasp", instance.getParentGroupId());
    }

    /**
     * Test of getParentArtifactId method, of class Model.
     */
    @Test
    public void testGetParentArtifactId() {
        Model instance = new Model();
        instance.setParentArtifactId("");
        String expResult = "";
        String result = instance.getParentArtifactId();
        assertEquals(expResult, result);
    }

    /**
     * Test of setParentArtifactId method, of class Model.
     */
    @Test
    public void testSetParentArtifactId() {
        String parentArtifactId = "something";
        Model instance = new Model();
        instance.setParentArtifactId(parentArtifactId);
        assertNotNull(instance.getParentArtifactId());
    }

    /**
     * Test of getParentVersion method, of class Model.
     */
    @Test
    public void testGetParentVersion() {
        Model instance = new Model();
        instance.setParentVersion("");
        String expResult = "";
        String result = instance.getParentVersion();
        assertEquals(expResult, result);
    }

    /**
     * Test of setParentVersion method, of class Model.
     */
    @Test
    public void testSetParentVersion() {
        String parentVersion = "1.0";
        Model instance = new Model();
        instance.setParentVersion(parentVersion);
        assertNotNull(instance.getParentVersion());
    }

    /**
     * Test of getLicenses method, of class Model.
     */
    @Test
    public void testGetLicenses() {
        Model instance = new Model();
        instance.addLicense(new License("name", "url"));
        List<License> expResult = new ArrayList<>();
        expResult.add(new License("name", "url"));
        List<License> result = instance.getLicenses();
        assertEquals(expResult, result);
    }

    /**
     * Test of addLicense method, of class Model.
     */
    @Test
    public void testAddLicense() {
        License license = new License("name", "url");
        Model instance = new Model();
        instance.addLicense(license);
        assertNotNull(instance.getLicenses());
    }

    /**
     * Test of processProperties method, of class Model.
     */
    @Test
    public void testProcessProperties() {

        String text = "This is a test of '${key}' '${nested}'";
        Model instance = new Model();
        instance.setName(text);
        instance.processProperties(null);
        String expResults = "This is a test of '${key}' '${nested}'";
        assertEquals(expResults, instance.getName());

        Properties prop = new Properties();
        prop.setProperty("key", "value");
        prop.setProperty("nested", "nested ${key}");

        instance.setName(text);
        instance.processProperties(prop);
        expResults = "This is a test of 'value' 'nested value'";
        assertEquals(expResults, instance.getName());
    }

    /**
     * Test of interpolateString method, of class Model.
     */
    @Test
    public void testInterpolateString() {
        Properties prop = new Properties();
        prop.setProperty("key", "value");
        prop.setProperty("nested", "nested ${key}");
        String text = "This is a test of '${key}' '${nested}'";
        String expResults = "This is a test of 'value' 'nested value'";
        String results = Model.interpolateString(text, prop);
        assertEquals(expResults, results);
    }

}
