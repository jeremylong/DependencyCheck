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
import java.util.List;
import org.junit.Assert;
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
        instance.parseHints(file);
        List<HintRule> hintRules = instance.getHintRules();
        List<VendorDuplicatingHintRule> vendorRules = instance.getVendorDuplicatingHintRules();
        assertEquals("Two duplicating hints should have been read", 2, vendorRules.size());
        assertEquals("Two hint rules should have been read", 2, hintRules.size());

        assertEquals("One add product should have been read", 1, hintRules.get(0).getAddProduct().size());
        assertEquals("One add vendor should have been read", 1, hintRules.get(0).getAddVendor().size());
        assertEquals("Two file name should have been read", 2, hintRules.get(1).getFileNames().size());

        assertEquals("add product name not found", "add product name", hintRules.get(0).getAddProduct().get(0).getName());
        assertEquals("add vendor name not found", "add vendor name", hintRules.get(0).getAddVendor().get(0).getName());
        assertEquals("given product name not found", "given product name", hintRules.get(0).getGivenProduct().get(0).getName());
        assertEquals("given vendor name not found", "given vendor name", hintRules.get(0).getGivenVendor().get(0).getName());

        assertEquals("spring file name not found", "spring", hintRules.get(1).getFileNames().get(0).getValue());
        assertEquals("file name 1 should not be case sensitive", false, hintRules.get(1).getFileNames().get(0).isCaseSensitive());
        assertEquals("file name 1 should not be a regex", false, hintRules.get(1).getFileNames().get(0).isRegex());
        assertEquals("file name 2 should be case sensitive", true, hintRules.get(1).getFileNames().get(1).isCaseSensitive());
        assertEquals("file name 2 should be a regex", true, hintRules.get(1).getFileNames().get(1).isRegex());

        assertEquals("sun duplicating vendor", "sun", vendorRules.get(0).getValue());
        assertEquals("sun duplicates vendor oracle", "oracle", vendorRules.get(0).getDuplicate());
    }

    /**
     * Test the application of the correct XSD by the parser by using a
     * hints-file with namespace
     * {@code https://jeremylong.github.io/DependencyCheck/dependency-hint.1.1.xsd}
     * that is using the version evidence for {@code<given>} that was introduced
     * with namespace
     * {@code https://jeremylong.github.io/DependencyCheck/dependency-hint.1.2.xsd}.
     * This should yield a specific SAXParseException that gets wrapped into a
     * HintParseException. We check for the correct error by searching for the
     * error-message of the SAXParser in the exception's message.
     */
    @Test
    public void testParseHintsXSDSelection() throws Exception {
        File file = BaseTest.getResourceAsFile(this, "hints_invalid.xml");
        HintParser instance = new HintParser();
        Exception exception = Assert.assertThrows(org.owasp.dependencycheck.xml.hints.HintParseException.class, () -> {
            instance.parseHints(file);
        });
        Assert.assertTrue(exception.getMessage().contains("Line=7, Column=133: cvc-enumeration-valid: Value 'version' is not facet-valid with respect to enumeration '[vendor, product]'. It must be a value from the enumeration."));

    }

    /**
     * Test of parseHints method, of class HintParser.
     */
    @Test
    public void testParseHints_InputStream() throws Exception {
        InputStream ins = BaseTest.getResourceAsStream(this, "hints_12.xml");
        HintParser instance = new HintParser();
        instance.parseHints(ins);
        List<HintRule> hintRules = instance.getHintRules();
        List<VendorDuplicatingHintRule> vendorRules = instance.getVendorDuplicatingHintRules();
        assertEquals("Zero duplicating hints should have been read", 0, vendorRules.size());
        assertEquals("Two hint rules should have been read", 2, hintRules.size());

        assertEquals("One given product should have been read in hint 0", 1, hintRules.get(0).getGivenProduct().size());
        assertEquals("One given vendor should have been read in hint 0", 1, hintRules.get(0).getGivenVendor().size());
        assertEquals("One given version should have been read in hint 0", 1, hintRules.get(0).getGivenVersion().size());

        assertEquals("One add product should have been read in hint 0", 1, hintRules.get(0).getAddProduct().size());
        assertEquals("One add vendor should have been read in hint 0", 1, hintRules.get(0).getAddVendor().size());
        assertEquals("One add version should have been read in hint 0", 1, hintRules.get(0).getAddVersion().size());
        assertEquals("Zero remove product should have been read in hint 0", 0, hintRules.get(0).getRemoveProduct().size());
        assertEquals("Zero remove vendor should have been read in hint 0", 0, hintRules.get(0).getRemoveVendor().size());
        assertEquals("Zero remove version should have been read in hint 0", 0, hintRules.get(0).getRemoveVersion().size());

        assertEquals("Zero given product should have been read in hint 1", 0, hintRules.get(1).getGivenProduct().size());
        assertEquals("Zero given vendor should have been read in hint 1", 0, hintRules.get(1).getGivenVendor().size());
        assertEquals("One given version should have been read in hint 1", 1, hintRules.get(1).getGivenVersion().size());

        assertEquals("One remove product should have been read in hint 1", 1, hintRules.get(1).getRemoveProduct().size());
        assertEquals("One remove vendor should have been read in hint 1", 1, hintRules.get(1).getRemoveVendor().size());
        assertEquals("One remove version should have been read in hint 1", 1, hintRules.get(1).getRemoveVersion().size());
        assertEquals("Zero add product should have been read in hint 1", 0, hintRules.get(1).getAddProduct().size());
        assertEquals("Zero add vendor should have been read in hint 1", 0, hintRules.get(1).getAddVendor().size());
        assertEquals("Zero add version should have been read in hint 1", 0, hintRules.get(1).getAddVersion().size());

        assertEquals("add product name not found in hint 0", "add product name", hintRules.get(0).getAddProduct().get(0).getName());
        assertEquals("add vendor name not found in hint 0", "add vendor name", hintRules.get(0).getAddVendor().get(0).getName());
        assertEquals("add version name not found in hint 0", "add version name", hintRules.get(0).getAddVersion().get(0).getName());

        assertEquals("given product name not found in hint 0", "given product name", hintRules.get(0).getGivenProduct().get(0).getName());
        assertEquals("given vendor name not found in hint 0", "given vendor name", hintRules.get(0).getGivenVendor().get(0).getName());
        assertEquals("given version name not found in hint 0", "given version name", hintRules.get(0).getGivenVersion().get(0).getName());

        assertEquals("given version name not found in hint 1", "given version name", hintRules.get(1).getGivenVersion().get(0).getName());

        assertEquals("add product name not found in hint 1", "remove product name", hintRules.get(1).getRemoveProduct().get(0).getName());
        assertEquals("add vendor name not found in hint 1", "remove vendor name", hintRules.get(1).getRemoveVendor().get(0).getName());
        assertEquals("add version name not found in hint 1", "remove version name", hintRules.get(1).getRemoveVersion().get(0).getName());

    }

    /**
     * Test of parseHints method, of class HintParser.
     */
    @Test
    public void testParseHintsWithRegex() throws Exception {
        InputStream ins = BaseTest.getResourceAsStream(this, "hints_13.xml");
        HintParser instance = new HintParser();
        instance.parseHints(ins);
        List<VendorDuplicatingHintRule> vendor = instance.getVendorDuplicatingHintRules();
        List<HintRule> rules = instance.getHintRules();

        assertEquals("Zero duplicating hints should have been read", 0, vendor.size());
        assertEquals("Two hint rules should have been read", 2, rules.size());

        assertEquals("One given product should have been read in hint 0", 1, rules.get(0).getGivenProduct().size());
        assertEquals("One given vendor should have been read in hint 0", 1, rules.get(0).getGivenVendor().size());
        assertEquals("One given version should have been read in hint 0", 1, rules.get(0).getGivenVersion().size());

        assertEquals("One add product should have been read in hint 0", 1, rules.get(0).getAddProduct().size());
        assertEquals("One add vendor should have been read in hint 0", 1, rules.get(0).getAddVendor().size());
        assertEquals("One add version should have been read in hint 0", 1, rules.get(0).getAddVersion().size());
        assertEquals("Zero remove product should have been read in hint 0", 0, rules.get(0).getRemoveProduct().size());
        assertEquals("Zero remove vendor should have been read in hint 0", 0, rules.get(0).getRemoveVendor().size());
        assertEquals("Zero remove version should have been read in hint 0", 0, rules.get(0).getRemoveVersion().size());

        assertEquals("Zero given product should have been read in hint 1", 0, rules.get(1).getGivenProduct().size());
        assertEquals("Zero given vendor should have been read in hint 1", 0, rules.get(1).getGivenVendor().size());
        assertEquals("One given version should have been read in hint 1", 1, rules.get(1).getGivenVersion().size());

        assertEquals("One remove product should have been read in hint 1", 1, rules.get(1).getRemoveProduct().size());
        assertEquals("One remove vendor should have been read in hint 1", 1, rules.get(1).getRemoveVendor().size());
        assertEquals("One remove version should have been read in hint 1", 1, rules.get(1).getRemoveVersion().size());
        assertEquals("Zero add product should have been read in hint 1", 0, rules.get(1).getAddProduct().size());
        assertEquals("Zero add vendor should have been read in hint 1", 0, rules.get(1).getAddVendor().size());
        assertEquals("Zero add version should have been read in hint 1", 0, rules.get(1).getAddVersion().size());

        assertEquals("add product name not found in hint 0", "add product name", rules.get(0).getAddProduct().get(0).getName());
        assertEquals("add vendor name not found in hint 0", "add vendor name", rules.get(0).getAddVendor().get(0).getName());
        assertEquals("add version name not found in hint 0", "add version name", rules.get(0).getAddVersion().get(0).getName());

        assertEquals("given product name not found in hint 0", "given product name", rules.get(0).getGivenProduct().get(0).getName());
        assertEquals("value not registered to be a regex for given product in hint 0", true, rules.get(0).getGivenProduct().get(0).isRegex());
        assertEquals("given vendor name not found in hint 0", "given vendor name", rules.get(0).getGivenVendor().get(0).getName());
        assertEquals("value not registered to be a regex for given vendor in hint 0", true, rules.get(0).getGivenVendor().get(0).isRegex());
        assertEquals("given version name not found in hint 0", "given version name", rules.get(0).getGivenVersion().get(0).getName());
        assertEquals("value not registered to not be a regex for given version in hint 0", false, rules.get(0).getGivenVersion().get(0).isRegex());

        assertEquals("given version name not found in hint 1", "given version name", rules.get(1).getGivenVersion().get(0).getName());
        assertEquals("value not registered to not be a regex by default for given version in hint 1", false, rules.get(1).getRemoveProduct().get(0).isRegex());

        assertEquals("remove product name not found in hint 1", "remove product name", rules.get(1).getRemoveProduct().get(0).getName());
        assertEquals("value not registered to not be a regex for product removal in hint 1", false, rules.get(1).getRemoveProduct().get(0).isRegex());
        assertEquals("remove vendor name not found in hint 1", "remove vendor name", rules.get(1).getRemoveVendor().get(0).getName());
        assertEquals("value not registered to not be a regex for vendor removal in hint 1", false, rules.get(1).getRemoveVendor().get(0).isRegex());
        assertEquals("remove version name not found in hint 1", "remove version name", rules.get(1).getRemoveVersion().get(0).getName());
        assertEquals("value not defaulted to not be a regex for vendor removal in hint 1", false, rules.get(1).getRemoveVersion().get(0).isRegex());

    }
}
