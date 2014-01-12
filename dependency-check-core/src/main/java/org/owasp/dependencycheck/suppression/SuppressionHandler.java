/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.suppression;

import java.util.ArrayList;
import java.util.List;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A handler to load suppression rules.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class SuppressionHandler extends DefaultHandler {

    /**
     * The suppress node, indicates the start of a new rule.
     */
    public static final String SUPPRESS = "suppress";
    /**
     * The file path element name.
     */
    public static final String FILE_PATH = "filePath";
    /**
     * The sha1 hash element name.
     */
    public static final String SHA1 = "sha1";
    /**
     * The CVE element name.
     */
    public static final String CVE = "cve";
    /**
     * The CPE element name.
     */
    public static final String CPE = "cpe";
    /**
     * The CWE element name.
     */
    public static final String CWE = "cwe";
    /**
     * The cvssBelow element name.
     */
    public static final String CVSS_BELOW = "cvssBelow";
    /**
     * A list of suppression rules.
     */
    private List<SuppressionRule> suppressionRules = new ArrayList<SuppressionRule>();

    /**
     * Get the value of suppressionRules.
     *
     * @return the value of suppressionRules
     */
    public List<SuppressionRule> getSuppressionRules() {
        return suppressionRules;
    }
    /**
     * The current rule being read.
     */
    private SuppressionRule rule;
    /**
     * The attributes of the node being read.
     */
    private Attributes currentAttributes;
    /**
     * The current node text being extracted from the element.
     */
    private StringBuffer currentText;

    /**
     * Handles the start element event.
     *
     * @param uri the uri of the element being processed
     * @param localName the local name of the element being processed
     * @param qName the qName of the element being processed
     * @param attributes the attributes of the element being processed
     * @throws SAXException thrown if there is an exception processing
     */
    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
        currentAttributes = null;
        currentText = new StringBuffer();

        if (SUPPRESS.equals(qName)) {
            rule = new SuppressionRule();
        } else if (FILE_PATH.equals(qName)) {
            currentAttributes = attributes;
        }
    }

    /**
     * Handles the end element event.
     *
     * @param uri the URI of the element
     * @param localName the local name of the element
     * @param qName the qName of the element
     * @throws SAXException thrown if there is an exception processing
     */
    @Override
    public void endElement(String uri, String localName, String qName) throws SAXException {
        if (SUPPRESS.equals(qName)) {
            suppressionRules.add(rule);
            rule = null;
        } else if (FILE_PATH.equals(qName)) {
            final PropertyType pt = processPropertyType();
            rule.setFilePath(pt);
        } else if (SHA1.equals(qName)) {
            rule.setSha1(currentText.toString());
        } else if (CPE.equals(qName)) {
            final PropertyType pt = processPropertyType();
            rule.addCpe(pt);
        } else if (CWE.equals(qName)) {
            rule.addCwe(currentText.toString());
        } else if (CVE.equals(qName)) {
            rule.addCve(currentText.toString());
        } else if (CVSS_BELOW.equals(qName)) {
            final float cvss = Float.parseFloat(currentText.toString());
            rule.addCvssBelow(cvss);
        }
    }

    /**
     * Collects the body text of the node being processed.
     *
     * @param ch the char array of text
     * @param start the start position to copy text from in the char array
     * @param length the number of characters to copy from the char array
     * @throws SAXException thrown if there is a parsing exception
     */
    @Override
    public void characters(char[] ch, int start, int length) throws SAXException {
        currentText.append(ch, start, length);
    }

    /**
     * Processes field members that have been collected during the characters and startElement method to construct a
     * PropertyType object.
     *
     * @return a PropertyType object
     */
    private PropertyType processPropertyType() {
        final PropertyType pt = new PropertyType();
        pt.setValue(currentText.toString());
        if (currentAttributes != null && currentAttributes.getLength() > 0) {
            final String regex = currentAttributes.getValue("regex");
            if (regex != null) {
                pt.setRegex(Boolean.parseBoolean(regex));
            }
            final String caseSensitive = currentAttributes.getValue("caseSensitive");
            if (regex != null) {
                pt.setCaseSensitive(Boolean.parseBoolean(caseSensitive));
            }
        }
        return pt;
    }
}
