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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.reporting;

import java.util.HashSet;
import java.util.Set;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.dependency.Identifier;

/**
 *
 * @author jerem
 */
public class EscapeToolTest {

    /**
     * Test of url method, of class EscapeTool.
     */
    @Test
    public void testUrl() {
        String text = null;
        EscapeTool instance = new EscapeTool();
        String expResult = null;
        String result = instance.url(text);
        assertEquals(expResult, result);
        
        text = "";
        expResult = "";
        result = instance.url(text);
        assertEquals(expResult, result);
        
        text = " ";
        expResult = "+";
        result = instance.url(text);
        assertEquals(expResult, result);
    }

    /**
     * Test of html method, of class EscapeTool.
     */
    @Test
    public void testHtml() {
        EscapeTool instance = new EscapeTool();
        String text = null;
        String expResult = null;
        String result = instance.html(text);
        assertEquals(expResult, result);
        
        text = "";
        expResult = "";
        result = instance.html(text);
        assertEquals(expResult, result);
        
        text = "<div>";
        expResult = "&lt;div&gt;";
        result = instance.html(text);
        assertEquals(expResult, result);
    }

    /**
     * Test of xml method, of class EscapeTool.
     */
    @Test
    public void testXml() {
        EscapeTool instance = new EscapeTool();
        String text = null;
        String expResult = null;
        String result = instance.xml(text);
        assertEquals(expResult, result);
        
        text = "";
        expResult = "";
        result = instance.xml(text);
        assertEquals(expResult, result);
        
        text = "<div>";
        expResult = "&lt;div&gt;";
        result = instance.xml(text);
        assertEquals(expResult, result);
    }

    /**
     * Test of json method, of class EscapeTool.
     */
    @Test
    public void testJson() {
        String text = null;
        EscapeTool instance = new EscapeTool();
        String expResult = null;
        String result = instance.json(text);
        assertEquals(expResult, result);
        
        text = "";
        expResult = "";
        result = instance.json(text);
        assertEquals(expResult, result);
        
        text = "test \"quote\"\"";
        expResult = "test \\\"quote\\\"\\\"";
        result = instance.json(text);
        assertEquals(expResult, result);
    }

    /**
     * Test of csv method, of class EscapeTool.
     */
    @Test
    public void testCsv() {
        String text = null;
        EscapeTool instance = new EscapeTool();
        String expResult = null;
        String result = instance.csv(text);
        assertEquals(expResult, result);
        
        text = "";
        expResult = "";
        result = instance.csv(text);
        assertEquals(expResult, result);
        
        text = "one, two";
        expResult = "\"one, two\"";
        result = instance.csv(text);
        assertEquals(expResult, result);
    }

    /**
     * Test of csvIdentifiers method, of class EscapeTool.
     */
    @Test
    public void testCsvIdentifiers() {
        EscapeTool instance = new EscapeTool();
        Set<Identifier> ids = null;
        String expResult = "";
        String result = instance.csvIdentifiers(ids);
        assertEquals(expResult, result);
        
        ids = new HashSet<>();
        expResult = "";
        result = instance.csvIdentifiers(ids);
        assertEquals(expResult, result);
        
        ids = new HashSet<>();
        ids.add(new Identifier("cpe", "cpe:/a:somegroup:something:1.0", ""));
        expResult = "";
        result = instance.csvIdentifiers(ids);
        assertEquals(expResult, result);
        
        ids = new HashSet<>();
        ids.add(new Identifier("gav", "somegroup:something:1.0", ""));
        expResult = "somegroup:something:1.0";
        result = instance.csvIdentifiers(ids);
        assertEquals(expResult, result);
        
        ids = new HashSet<>();
        ids.add(new Identifier("cpe", "cpe:/a:somegroup:something:1.0", ""));
        ids.add(new Identifier("gav", "somegroup:something:1.0", ""));
        expResult = "somegroup:something:1.0";
        result = instance.csvIdentifiers(ids);
        assertEquals(expResult, result);
        
        ids = new HashSet<>();
        ids.add(new Identifier("cpe", "cpe:/a:somegroup:something:1.0", ""));
        ids.add(new Identifier("gav", "somegroup:something:1.0", ""));
        ids.add(new Identifier("gav", "somegroup2:something:1.2", ""));
        expResult = "\"somegroup:something:1.0, somegroup2:something:1.2\"";
        String expResult2 = "\"somegroup2:something:1.2, somegroup:something:1.0\"";
        result = instance.csvIdentifiers(ids);
        assertTrue(expResult.equals(result) || expResult2.equals(result));
    }

    /**
     * Test of csvCpe method, of class EscapeTool.
     */
    @Test
    public void testCsvCpe() {
        EscapeTool instance = new EscapeTool();
        Set<Identifier> ids = null;
        String expResult = "";
        String result = instance.csvCpe(ids);
        assertEquals(expResult, result);
        
        ids = new HashSet<>();
        expResult = "";
        result = instance.csvCpe(ids);
        assertEquals(expResult, result);
        
        ids = new HashSet<>();
        ids.add(new Identifier("gav", "somegroup:something:1.0", ""));
        expResult = "";
        result = instance.csvCpe(ids);
        assertEquals(expResult, result);
        
        ids = new HashSet<>();
        ids.add(new Identifier("cpe", "cpe:/a:somegroup:something:1.0", ""));
        expResult = "cpe:/a:somegroup:something:1.0";
        result = instance.csvCpe(ids);
        assertEquals(expResult, result);
        
        ids = new HashSet<>();
        ids.add(new Identifier("cpe", "cpe:/a:somegroup:something:1.0", ""));
        ids.add(new Identifier("gav", "somegroup:something:1.0", ""));
        expResult = "cpe:/a:somegroup:something:1.0";
        result = instance.csvCpe(ids);
        assertEquals(expResult, result);
        
        ids = new HashSet<>();
        ids.add(new Identifier("cpe", "cpe:/a:somegroup:something:1.0", ""));
        ids.add(new Identifier("gav", "somegroup:something:1.0", ""));
        ids.add(new Identifier("cpe", "cpe:/a:somegroup2:something:1.2", ""));
        expResult = "\"cpe:/a:somegroup:something:1.0, cpe:/a:somegroup2:something:1.2\"";
        String expResult2 = "\"cpe:/a:somegroup2:something:1.2, cpe:/a:somegroup:something:1.0\"";
        result = instance.csvCpe(ids);
        assertTrue(expResult.equals(result) || expResult2.equals(result));
    }
}
