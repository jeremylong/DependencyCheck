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
package org.owasp.dependencycheck.xml.suppression;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import javax.annotation.concurrent.NotThreadSafe;
import org.owasp.dependencycheck.exception.ParseException;
import org.owasp.dependencycheck.utils.DateUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A handler to load suppression rules.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class SuppressionHandler extends DefaultHandler {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SuppressionHandler.class);

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
     * The vulnerabilityName element name.
     */
    public static final String VULNERABILITY_NAME = "vulnerabilityName";

    /**
     * The CVE element name.
     */
    public static final String NOTES = "notes";

    /**
     * The CPE element name.
     */
    public static final String CPE = "cpe";
    /**
     * The CWE element name.
     */
    public static final String CWE = "cwe";
    /**
     * The GAV element name.
     */
    public static final String GAV = "gav";
    /**
     * The Package URL element name.
     */
    public static final String PACKAGE_URL = "packageUrl";
    /**
     * The cvssBelow element name.
     */
    public static final String CVSS_BELOW = "cvssBelow";
    /**
     * A list of suppression rules.
     */
    private final List<SuppressionRule> suppressionRules = new ArrayList<>();
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
    private StringBuilder currentText;
    /**
     * The suppression rule filter.
     */
    private SuppressionRuleFilter filter;

    /**
     * Get the value of suppressionRules.
     *
     * @return the value of suppressionRules
     */
    public List<SuppressionRule> getSuppressionRules() {
        return suppressionRules;
    }

    /**
     * Constructs a Suppression Handler.
     *
     * @param filter The suppression rule filter used when loading the
     * suppression rules. This is used to differentiate vulnerability
     * suppression rules from CPE suppression rules.
     */
    public SuppressionHandler(SuppressionRuleFilter filter) {
        this.filter = filter;
    }

    /**
     * Handles the start element event.
     *
     * @param uri the URI of the element being processed
     * @param localName the local name of the element being processed
     * @param qName the qName of the element being processed
     * @param attributes the attributes of the element being processed
     * @throws SAXException thrown if there is an exception processing
     */
    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
        currentAttributes = attributes;
        currentText = new StringBuilder();
        if (SUPPRESS.equals(qName)) {
            rule = new SuppressionRule();
            final String base = currentAttributes.getValue("base");
            if (base != null) {
                rule.setBase(Boolean.parseBoolean(base));
            } else {
                rule.setBase(false);
            }
            final String until = currentAttributes.getValue("until");
            if (until != null) {
                try {
                    rule.setUntil(DateUtil.parseXmlDate(until));
                } catch (ParseException ex) {
                    throw new SAXException("Unable to parse until date in suppression file: " + until, ex);
                }
            }
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
        if (null != qName) {
            switch (qName) {
                case SUPPRESS:
                    if (rule.getUntil() != null && rule.getUntil().before(Calendar.getInstance())) {
                        LOGGER.info("Suppression is expired for rule: {}", rule);
                    } else if (filter != null && filter.filter(rule)) {
                        LOGGER.debug("Filtering {} for {}", rule.toString(), filter.getName());
                    } else {
                        suppressionRules.add(rule);
                    }
                    rule = null;
                    break;
                case FILE_PATH:
                    rule.setFilePath(processPropertyType());
                    break;
                case SHA1:
                    rule.setSha1(currentText.toString().trim());
                    break;
                case GAV:
                    rule.setGav(processPropertyType());
                    break;
                case PACKAGE_URL:
                    rule.setPackageUrl(processPropertyType());
                    break;
                case CPE:
                    rule.addCpe(processPropertyType());
                    break;
                case CWE:
                    rule.addCwe(currentText.toString().trim());
                    break;
                case CVE:
                    rule.addCve(currentText.toString().trim());
                    break;
                case VULNERABILITY_NAME:
                    rule.addVulnerabilityName(processPropertyType());
                    break;
                case NOTES:
                    rule.addNotes(currentText.toString().trim());
                    break;
                case CVSS_BELOW:
                    final float cvss = Float.parseFloat(currentText.toString().trim());
                    rule.addCvssBelow(cvss);
                    break;
                default:
                    break;
            }
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
     * Processes field members that have been collected during the characters
     * and startElement method to construct a PropertyType object.
     *
     * @return a PropertyType object
     */
    private PropertyType processPropertyType() {
        final PropertyType pt = new PropertyType();
        pt.setValue(currentText.toString().trim());
        if (currentAttributes != null && currentAttributes.getLength() > 0) {
            final String regex = currentAttributes.getValue("regex");
            if (regex != null) {
                pt.setRegex(Boolean.parseBoolean(regex));
            }
            final String caseSensitive = currentAttributes.getValue("caseSensitive");
            if (caseSensitive != null) {
                pt.setCaseSensitive(Boolean.parseBoolean(caseSensitive));
            }
        }
        return pt;
    }
}
