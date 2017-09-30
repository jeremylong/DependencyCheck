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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.nvd;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import javax.annotation.concurrent.NotThreadSafe;
import org.apache.lucene.index.CorruptIndexException;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.dependency.Reference;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.helpers.DefaultHandler;
//CSOFF: AvoidStarImport
import static org.owasp.dependencycheck.data.update.nvd.NvdCve20Handler.AttributeValues.*;
//CSON: AvoidStarImport

/**
 * A SAX Handler that will parse the NVD CVE XML (schema version 2.0).
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class NvdCve20Handler extends DefaultHandler {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NvdCve20Handler.class);
    /**
     * the current supported schema version.
     */
    private static final String CURRENT_SCHEMA_VERSION = "2.0";
    /**
     * a possible attribute value of the {@link AttributeValues#XML_LANG}
     * attribute
     */
    private static final String EN = "en";
    /**
     * the prefix of the node text of a CPE
     */
    private static final String CPE_NODE_TEXT_PREFIX = "cpe:/a:";
    /**
     * the node text of an entry marked for deletion
     */
    private static final String REJECT_NODE_TEXT = "** REJECT **";
    /**
     * the current element.
     */
    private final Element current = new Element();
    /**
     * the text of the node.
     */
    private StringBuilder nodeText;
    /**
     * the vulnerability.
     */
    private Vulnerability vulnerability;
    /**
     * a reference for the cve.
     */
    private Reference reference;
    /**
     * flag indicating whether the application has a cpe.
     */
    private boolean hasApplicationCpe = false;
    /**
     * The total number of entries parsed.
     */
    private int totalNumberOfEntries;

    /**
     * The total number of application entries parsed.
     */
    private int totalNumberOfApplicationEntries;
    /**
     * the cve database.
     */
    private CveDB cveDB;

    /**
     * A list of CVE entries and associated VulnerableSoftware entries that
     * contain previous entries.
     */
    private Map<String, List<VulnerableSoftware>> prevVersionVulnMap;

    /**
     * Get the value of totalNumberOfEntries.
     *
     * @return the value of totalNumberOfEntries
     */
    public int getTotalNumberOfEntries() {
        return totalNumberOfEntries;
    }

    /**
     * Get the value of totalNumberOfApplicationEntries.
     *
     * @return the value of totalNumberOfApplicationEntries
     */
    public int getTotalNumberOfApplicationEntries() {
        return totalNumberOfApplicationEntries;
    }

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
        current.setNode(qName);
        if (current.isEntryNode()) {
            hasApplicationCpe = false;
            vulnerability = new Vulnerability();
            vulnerability.setName(attributes.getValue(ID));
        } else if (current.isVulnProductNode()) {
            nodeText = new StringBuilder(100);
        } else if (current.isVulnReferencesNode()) {
            final String lang = attributes.getValue(XML_LANG);
            if (EN.equals(lang)) {
                reference = new Reference();
            } else {
                reference = null;
            }
        } else if (reference != null && current.isVulnReferenceNode()) {
            reference.setUrl(attributes.getValue(HREF));
            nodeText = new StringBuilder(130);
        } else if (reference != null && current.isVulnSourceNode()) {
            nodeText = new StringBuilder(30);
        } else if (current.isVulnSummaryNode()) {
            nodeText = new StringBuilder(500);
        } else if (current.isNVDNode()) {
            final String nvdVer = attributes.getValue(NVD_XML_VERSION);
            if (!CURRENT_SCHEMA_VERSION.equals(nvdVer)) {
                throw new SAXNotSupportedException("Schema version " + nvdVer + " is not supported");
            }
        } else if (current.isVulnCWENode()) {
            vulnerability.setCwe(attributes.getValue(ID));
        } else if (current.isCVSSScoreNode()) {
            nodeText = new StringBuilder(5);
        } else if (current.isCVSSAccessVectorNode()) {
            nodeText = new StringBuilder(20);
        } else if (current.isCVSSAccessComplexityNode()) {
            nodeText = new StringBuilder(20);
        } else if (current.isCVSSAuthenticationNode()) {
            nodeText = new StringBuilder(20);
        } else if (current.isCVSSAvailabilityImpactNode()) {
            nodeText = new StringBuilder(20);
        } else if (current.isCVSSConfidentialityImpactNode()) {
            nodeText = new StringBuilder(20);
        } else if (current.isCVSSIntegrityImpactNode()) {
            nodeText = new StringBuilder(20);
        }
    }

    @Override
    public void characters(char[] ch, int start, int length) throws SAXException {
        if (nodeText != null) {
            nodeText.append(ch, start, length);
        }
    }

    @Override
    public void endElement(String uri, String localName, String qName) throws SAXException {
        current.setNode(qName);
        if (current.isEntryNode()) {
            totalNumberOfEntries += 1;
            if (hasApplicationCpe) {
                totalNumberOfApplicationEntries += 1;
                try {
                    saveEntry(vulnerability);
                } catch (DatabaseException | IOException ex) {
                    throw new SAXException(ex);
                }
            }
            vulnerability = null;
        } else if (current.isCVSSScoreNode()) {
            try {
                final float score = Float.parseFloat(nodeText.toString());
                vulnerability.setCvssScore(score);
            } catch (NumberFormatException ex) {
                LOGGER.error("Error parsing CVSS Score.");
                LOGGER.debug("", ex);
            }
            nodeText = null;
        } else if (current.isCVSSAccessVectorNode()) {
            vulnerability.setCvssAccessVector(nodeText.toString());
            nodeText = null;
        } else if (current.isCVSSAccessComplexityNode()) {
            vulnerability.setCvssAccessComplexity(nodeText.toString());
            nodeText = null;
        } else if (current.isCVSSAuthenticationNode()) {
            vulnerability.setCvssAuthentication(nodeText.toString());
            nodeText = null;
        } else if (current.isCVSSAvailabilityImpactNode()) {
            vulnerability.setCvssAvailabilityImpact(nodeText.toString());
            nodeText = null;
        } else if (current.isCVSSConfidentialityImpactNode()) {
            vulnerability.setCvssConfidentialityImpact(nodeText.toString());
            nodeText = null;
        } else if (current.isCVSSIntegrityImpactNode()) {
            vulnerability.setCvssIntegrityImpact(nodeText.toString());
            nodeText = null;
        } else if (current.isVulnProductNode()) {
            final String cpe = nodeText.toString();
            if (cpe.startsWith(CPE_NODE_TEXT_PREFIX)) {
                hasApplicationCpe = true;
                vulnerability.addVulnerableSoftware(cpe);
            }
            nodeText = null;
        } else if (reference != null && current.isVulnReferencesNode()) {
            vulnerability.addReference(reference);
            reference = null;
        } else if (reference != null && current.isVulnReferenceNode()) {
            reference.setName(nodeText.toString());
            nodeText = null;
        } else if (reference != null && current.isVulnSourceNode()) {
            reference.setSource(nodeText.toString());
            nodeText = null;
        } else if (current.isVulnSummaryNode()) {
            vulnerability.setDescription(nodeText.toString());
            if (nodeText.indexOf(REJECT_NODE_TEXT) >= 0) {
                hasApplicationCpe = true; //ensure we process this to delete the vuln
            }
            nodeText = null;
        }
    }

    /**
     * Sets the cveDB.
     *
     * @param db a reference to the CveDB
     */
    public void setCveDB(CveDB db) {
        cveDB = db;
    }

    /**
     * Sets the prevVersionVulnMap.
     *
     * @param map the map of vulnerable software with previous versions being
     * vulnerable
     */
    public void setPrevVersionVulnMap(Map<String, List<VulnerableSoftware>> map) {
        prevVersionVulnMap = map;
    }

    /**
     * Saves a vulnerability to the CVE Database.
     *
     * @param vuln the vulnerability to store in the database
     * @throws DatabaseException thrown if there is an error writing to the
     * database
     * @throws CorruptIndexException is thrown if the CPE Index is corrupt
     * @throws IOException thrown if there is an IOException with the CPE Index
     */
    private void saveEntry(Vulnerability vuln) throws DatabaseException, CorruptIndexException, IOException {
        final String cveName = vuln.getName();
        if (prevVersionVulnMap != null && prevVersionVulnMap.containsKey(cveName)) {
            final List<VulnerableSoftware> vulnSoftware = prevVersionVulnMap.get(cveName);
            for (VulnerableSoftware vs : vulnSoftware) {
                vuln.updateVulnerableSoftware(vs);
            }
        }
        if (cveDB != null) {
            cveDB.updateVulnerability(vuln);
        }
    }

    // <editor-fold defaultstate="collapsed" desc="The Element Class that maintains state information about the current node">
    /**
     * A simple class to maintain information about the current element while
     * parsing the NVD CVE XML.
     */
    protected static class Element {

        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String NVD = "nvd";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String ENTRY = "entry";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String VULN_PRODUCT = "vuln:product";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String VULN_REFERENCES = "vuln:references";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String VULN_SOURCE = "vuln:source";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String VULN_REFERENCE = "vuln:reference";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String VULN_SUMMARY = "vuln:summary";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String VULN_CWE = "vuln:cwe";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String CVSS_SCORE = "cvss:score";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String CVSS_ACCESS_VECTOR = "cvss:access-vector";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String CVSS_ACCESS_COMPLEXITY = "cvss:access-complexity";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String CVSS_AUTHENTICATION = "cvss:authentication";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String CVSS_CONFIDENTIALITY_IMPACT = "cvss:confidentiality-impact";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String CVSS_INTEGRITY_IMPACT = "cvss:integrity-impact";
        /**
         * A node type in the NVD CVE Schema 2.0
         */
        public static final String CVSS_AVAILABILITY_IMPACT = "cvss:availability-impact";
        /**
         * The current node.
         */
        private String node;

        /**
         * Gets the value of node.
         *
         * @return the value of node
         */
        public String getNode() {
            return this.node;
        }

        /**
         * Sets the value of node.
         *
         * @param node new value of node
         */
        public void setNode(String node) {
            this.node = node;
        }

        /**
         * Checks if the handler is at the NVD node.
         *
         * @return true or false
         */
        public boolean isNVDNode() {
            return NVD.equals(node);
        }

        /**
         * Checks if the handler is at the ENTRY node.
         *
         * @return true or false
         */
        public boolean isEntryNode() {
            return ENTRY.equals(node);
        }

        /**
         * Checks if the handler is at the VULN_PRODUCT node.
         *
         * @return true or false
         */
        public boolean isVulnProductNode() {
            return VULN_PRODUCT.equals(node);
        }

        /**
         * Checks if the handler is at the REFERENCES node.
         *
         * @return true or false
         */
        public boolean isVulnReferencesNode() {
            return VULN_REFERENCES.equals(node);
        }

        /**
         * Checks if the handler is at the REFERENCE node.
         *
         * @return true or false
         */
        public boolean isVulnReferenceNode() {
            return VULN_REFERENCE.equals(node);
        }

        /**
         * Checks if the handler is at the VULN_SOURCE node.
         *
         * @return true or false
         */
        public boolean isVulnSourceNode() {
            return VULN_SOURCE.equals(node);
        }

        /**
         * Checks if the handler is at the VULN_SUMMARY node.
         *
         * @return true or false
         */
        public boolean isVulnSummaryNode() {
            return VULN_SUMMARY.equals(node);
        }

        /**
         * Checks if the handler is at the VULN_CWE node.
         *
         * @return true or false
         */
        public boolean isVulnCWENode() {
            return VULN_CWE.equals(node);
        }

        /**
         * Checks if the handler is at the CVSS_SCORE node.
         *
         * @return true or false
         */
        public boolean isCVSSScoreNode() {
            return CVSS_SCORE.equals(node);
        }

        /**
         * Checks if the handler is at the CVSS_ACCESS_VECTOR node.
         *
         * @return true or false
         */
        public boolean isCVSSAccessVectorNode() {
            return CVSS_ACCESS_VECTOR.equals(node);
        }

        /**
         * Checks if the handler is at the CVSS_ACCESS_COMPLEXITY node.
         *
         * @return true or false
         */
        public boolean isCVSSAccessComplexityNode() {
            return CVSS_ACCESS_COMPLEXITY.equals(node);
        }

        /**
         * Checks if the handler is at the CVSS_AUTHENTICATION node.
         *
         * @return true or false
         */
        public boolean isCVSSAuthenticationNode() {
            return CVSS_AUTHENTICATION.equals(node);
        }

        /**
         * Checks if the handler is at the CVSS_CONFIDENTIALITY_IMPACT node.
         *
         * @return true or false
         */
        public boolean isCVSSConfidentialityImpactNode() {
            return CVSS_CONFIDENTIALITY_IMPACT.equals(node);
        }

        /**
         * Checks if the handler is at the CVSS_INTEGRITY_IMPACT node.
         *
         * @return true or false
         */
        public boolean isCVSSIntegrityImpactNode() {
            return CVSS_INTEGRITY_IMPACT.equals(node);
        }

        /**
         * Checks if the handler is at the CVSS_AVAILABILITY_IMPACT node.
         *
         * @return true or false
         */
        public boolean isCVSSAvailabilityImpactNode() {
            return CVSS_AVAILABILITY_IMPACT.equals(node);
        }
    }
    // </editor-fold>

    /**
     * A simple class to maintain information about the attribute values
     * encountered while parsing the NVD CVE XML.
     */
    protected static class AttributeValues {

        /**
         * An attribute in the NVD CVE Schema 2.0
         */
        protected static final String ID = "id";
        /**
         * An attribute in the NVD CVE Schema 2.0
         */
        protected static final String XML_LANG = "xml:lang";
        /**
         * An attribute in the NVD CVE Schema 2.0
         */
        protected static final String HREF = "href";
        /**
         * An attribute in the NVD CVE Schema 2.0
         */
        protected static final String NVD_XML_VERSION = "nvd_xml_version";
    }
}
