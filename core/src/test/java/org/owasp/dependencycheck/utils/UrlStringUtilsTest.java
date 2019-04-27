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
package org.owasp.dependencycheck.utils;

import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author jeremy long
 */
public class UrlStringUtilsTest {

    /**
     * Test of containsUrl method, of class UrlStringUtils.
     */
    @Test
    public void testContainsUrl() {
        String text = "Test of https://github.com";
        assertTrue(UrlStringUtils.containsUrl(text));
        text = "Test of github.com";
        assertFalse(UrlStringUtils.containsUrl(text));
    }

    /**
     * Test of isUrl method, of class UrlStringUtils.
     */
    @Test
    public void testIsUrl() {
        String text = "https://github.com";
        assertTrue(UrlStringUtils.isUrl(text));
        text = "simple text";
        assertFalse(UrlStringUtils.isUrl(text));
    }

    /**
     * Test of extractImportantUrlData method, of class UrlStringUtils.
     */
    @Test
    public void testExtractImportantUrlData() throws Exception {
        String text = "http://github.com/jeremylong/DependencyCheck/.gitignore";
        List<String> expResult = Arrays.asList("jeremylong", "DependencyCheck", "gitignore");
        List<String> result = UrlStringUtils.extractImportantUrlData(text);
        assertEquals(expResult, result);
        
        text = "http://jeremylong.github.io/DependencyCheck/index.html";
        expResult = Arrays.asList("jeremylong", "DependencyCheck", "index");
        result = UrlStringUtils.extractImportantUrlData(text);
        assertEquals(expResult, result);
        
        text = "http://example.com/jeremylong/DependencyCheck/something";
        expResult = Arrays.asList("example", "jeremylong", "DependencyCheck", "something");
        result = UrlStringUtils.extractImportantUrlData(text);
        assertEquals(expResult, result);
    }

}
