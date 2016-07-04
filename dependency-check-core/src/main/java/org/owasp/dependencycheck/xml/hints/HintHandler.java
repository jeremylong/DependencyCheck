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

import java.util.ArrayList;
import java.util.List;
import org.owasp.dependencycheck.dependency.Confidence;
import org.owasp.dependencycheck.suppression.PropertyType;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A handler to load hint rules.
 *
 * @author Jeremy Long
 */
public class HintHandler extends DefaultHandler {

    //<editor-fold defaultstate="collapsed" desc="Element and attribute names">
    /**
     * Element name.
     */
    private static final String HINT = "hint";
    /**
     * Element name.
     */
    private static final String GIVEN = "given";
    /**
     * Element name.
     */
    private static final String ADD = "add";
    /**
     * Element name.
     */
    private static final String EVIDENCE = "evidence";
    /**
     * Element name.
     */
    private static final String FILE_NAME = "fileName";
    /**
     * Element name.
     */
    private static final String VENDOR_DUPLICATING_RULE = "vendorDuplicatingHint";
    /**
     * Attribute name.
     */
    private static final String DUPLICATE = "duplicate";
    /**
     * Attribute name.
     */
    private static final String VENDOR = "vendor";
    /**
     * Attribute name.
     */
    private static final String CONFIDENCE = "confidence";
    /**
     * Attribute name.
     */
    private static final String VALUE = "value";
    /**
     * Attribute name.
     */
    private static final String NAME = "name";
    /**
     * Attribute name.
     */
    private static final String SOURCE = "source";
    /**
     * Attribute name.
     */
    private static final String TYPE = "type";
    /**
     * Attribute name.
     */
    private static final String CASE_SENSITIVE = "caseSensitive";
    /**
     * Attribute name.
     */
    private static final String REGEX = "regex";
    /**
     * Attribute name.
     */
    private static final String CONTAINS = "contains";
    //</editor-fold>

    /**
     * The list of hint rules.
     */
    private final List<HintRule> hintRules = new ArrayList<HintRule>();

    /**
     * Returns the list of hint rules.
     *
     * @return the value of hintRules
     */
    public List<HintRule> getHintRules() {
        return hintRules;
    }

    /**
     * The list of vendor duplicating hint rules.
     */
    private final List<VendorDuplicatingHintRule> vendorDuplicatingHintRules = new ArrayList<VendorDuplicatingHintRule>();

    /**
     * Returns the list of vendor duplicating hint rules.
     *
     * @return the list of vendor duplicating hint rules
     */
    public List<VendorDuplicatingHintRule> getVendorDuplicatingHintRules() {
        return vendorDuplicatingHintRules;
    }

    /**
     * The current rule being read.
     */
    private HintRule rule;
    /**
     * The current state of the parent node (to differentiate between 'add' and
     * 'given').
     */
    private boolean inAddNode = false;

    /**
     * Handles the start element event.
     *
     * @param uri the uri of the element being processed
     * @param localName the local name of the element being processed
     * @param qName the qName of the element being processed
     * @param attr the attributes of the element being processed
     * @throws SAXException thrown if there is an exception processing
     */
    @Override
    public void startElement(String uri, String localName, String qName, Attributes attr) throws SAXException {
        if (HINT.equals(qName)) {
            rule = new HintRule();
        } else if (ADD.equals(qName)) {
            inAddNode = true;
        } else if (GIVEN.equals(qName)) {
            inAddNode = false;
        } else if (EVIDENCE.equals(qName)) {
            final String hintType = attr.getValue(TYPE);
            if (VENDOR.equals(hintType)) {
                if (inAddNode) {
                    rule.addAddVendor(attr.getValue(SOURCE),
                            attr.getValue(NAME),
                            attr.getValue(VALUE),
                            Confidence.valueOf(attr.getValue(CONFIDENCE)));
                } else {
                    rule.addGivenVendor(attr.getValue(SOURCE),
                            attr.getValue(NAME),
                            attr.getValue(VALUE),
                            Confidence.valueOf(attr.getValue(CONFIDENCE)));
                }
            } else if (inAddNode) {
                rule.addAddProduct(attr.getValue(SOURCE),
                        attr.getValue(NAME),
                        attr.getValue(VALUE),
                        Confidence.valueOf(attr.getValue(CONFIDENCE)));
            } else {
                rule.addGivenProduct(attr.getValue(SOURCE),
                        attr.getValue(NAME),
                        attr.getValue(VALUE),
                        Confidence.valueOf(attr.getValue(CONFIDENCE)));
            }
        } else if (FILE_NAME.equals(qName)) {
            final PropertyType pt = new PropertyType();
            pt.setValue(attr.getValue(CONTAINS));
            if (attr.getLength() > 0) {
                final String regex = attr.getValue(REGEX);
                if (regex != null) {
                    pt.setRegex(Boolean.parseBoolean(regex));
                }
                final String caseSensitive = attr.getValue(CASE_SENSITIVE);
                if (caseSensitive != null) {
                    pt.setCaseSensitive(Boolean.parseBoolean(caseSensitive));
                }
            }
            rule.addFilename(pt);
        } else if (VENDOR_DUPLICATING_RULE.equals(qName)) {
            vendorDuplicatingHintRules.add(new VendorDuplicatingHintRule(attr.getValue(VALUE), attr.getValue(DUPLICATE)));
        }
    }
    
    /**
     * Handles the end element event.
     *
     * @param uri the element's uri
     * @param localName the local name
     * @param qName the qualified name
     * @throws SAXException thrown if there is an exception processing the
     * element
     */
    @Override
    public void endElement(String uri, String localName, String qName) throws SAXException {
        if (HINT.equals(qName) && rule != null) {
            hintRules.add(rule);
            rule = null;
        }
    }
}
