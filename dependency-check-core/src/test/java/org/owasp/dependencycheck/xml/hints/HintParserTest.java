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
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.hints;

import java.io.File;
import java.io.InputStream;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import org.owasp.dependencycheck.BaseTest;

/**
 *
 * @author Jeremy Long
 */
public class HintParserTest extends BaseTest {

    /**
     * Test of parseHints method, of class HintParser.
     */
    @Test
    public void testParseHints_File() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "hints.xml");
        HintParser instance = new HintParser();
        Hints results = instance.parseHints(file);
        assertEquals("Two duplicating hints should have been read", 2, results.getVendorDuplicatingHintRules().size());
        assertEquals("Two hint rules should have been read", 2, results.getHintRules().size());
    }

    /**
     * Test of parseHints method, of class HintParser.
     */
    @Test
    public void testParseHints_InputStream() throws Exception {
        InputStream ins = BaseTest.getResourceAsStream(this, "hints.xml");
        HintParser instance = new HintParser();
        Hints results = instance.parseHints(ins);
        assertEquals("Two duplicating hints should have been read", 2, results.getVendorDuplicatingHintRules().size());
        assertEquals("Two hint rules should have been read", 2, results.getHintRules().size());
        assertEquals("One add product should have been read", 1, results.getHintRules().get(0).getAddProduct().size());
        assertEquals("One add vendor should have been read", 1, results.getHintRules().get(0).getAddVendor().size());
        assertEquals("Two file name should have been read", 2, results.getHintRules().get(1).getFilenames().size());

        assertEquals("add product name not found", "add product name", results.getHintRules().get(0).getAddProduct().get(0).getName());
        assertEquals("add vendor name not found", "add vendor name", results.getHintRules().get(0).getAddVendor().get(0).getName());
        assertEquals("given product name not found", "given product name", results.getHintRules().get(0).getGivenProduct().get(0).getName());
        assertEquals("given vendor name not found", "given vendor name", results.getHintRules().get(0).getGivenVendor().get(0).getName());

        assertEquals("spring file name not found", "spring", results.getHintRules().get(1).getFilenames().get(0).getValue());
        assertEquals("file name 1 should not be case sensitive", false, results.getHintRules().get(1).getFilenames().get(0).isCaseSensitive());
        assertEquals("file name 1 should not be a regex", false, results.getHintRules().get(1).getFilenames().get(0).isRegex());
        assertEquals("file name 2 should be case sensitive", true, results.getHintRules().get(1).getFilenames().get(1).isCaseSensitive());
        assertEquals("file name 2 should be a regex", true, results.getHintRules().get(1).getFilenames().get(1).isRegex());
    }
}
