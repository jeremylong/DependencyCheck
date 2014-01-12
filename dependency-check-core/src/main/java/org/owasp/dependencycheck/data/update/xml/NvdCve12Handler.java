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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.xml;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A SAX Handler that will parse the NVD CVE XML (schema version 1.2). This
 * parses the xml and retrieves a listing of CPEs that have previous versions
 * specified. The previous version information is not in the 2.0 version of the
 * schema and is useful to ensure accurate identification (or at least
 * complete).
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class NvdCve12Handler extends DefaultHandler {

    /**
     * the supported schema version.
     */
    private static final String CURRENT_SCHEMA_VERSION = "1.2";
    /**
     * the current vulnerability.
     */
    private String vulnerability;
    /**
     * a list of vulnerable software.
     */
    private List<VulnerableSoftware> software;
    /**
     * the vendor name.
     */
    private String vendor;
    /**
     * the product name.
     */
    private String product;
    /**
     * if the nvd cve should be skipped because it was rejected.
     */
    private boolean skip = false;
    /**
     * flag indicating if there is a previous version.
     */
    private boolean hasPreviousVersion = false;
    /**
     * The current element.
     */
    private final Element current = new Element();
    /**
     * a map of vulnerabilities.
     */
    private Map<String, List<VulnerableSoftware>> vulnerabilities;

    /**
     * Get the value of vulnerabilities.
     *
     * @return the value of vulnerabilities
     */
    public Map<String, List<VulnerableSoftware>> getVulnerabilities() {
        return vulnerabilities;
    }

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
        current.setNode(qName);
        if (current.isEntryNode()) {
            vendor = null;
            product = null;
            hasPreviousVersion = false;
            final String reject = attributes.getValue("reject");
            skip = "1".equals(reject);
            if (!skip) {
                vulnerability = attributes.getValue("name");
                software = new ArrayList<VulnerableSoftware>();
            } else {
                vulnerability = null;
                software = null;
            }
        } else if (!skip && current.isProdNode()) {

            vendor = attributes.getValue("vendor");
            product = attributes.getValue("name");
        } else if (!skip && current.isVersNode()) {
            final String prev = attributes.getValue("prev");
            if (prev != null && "1".equals(prev)) {
                hasPreviousVersion = true;
                final String edition = attributes.getValue("edition");
                final String num = attributes.getValue("num");

                /*yes yes, this may not actually be an "a" - it could be an OS, etc. but for our
                 purposes this is good enough as we won't use this if we don't find a corresponding "a"
                 in the nvd cve 2.0. */
                String cpe = "cpe:/a:" + vendor + ":" + product;
                if (num != null) {
                    cpe += ":" + num;
                }
                if (edition != null) {
                    cpe += ":" + edition;
                }
                final VulnerableSoftware vs = new VulnerableSoftware();
                vs.setCpe(cpe);
                vs.setPreviousVersion(prev);
                software.add(vs);
            }
        } else if (current.isNVDNode()) {
            final String nvdVer = attributes.getValue("nvd_xml_version");
            if (!CURRENT_SCHEMA_VERSION.equals(nvdVer)) {
                throw new SAXNotSupportedException("Schema version " + nvdVer + " is not supported");
            }
            vulnerabilities = new HashMap<String, List<VulnerableSoftware>>();
        }
    }

    @Override
    public void endElement(String uri, String localName, String qName) throws SAXException {
        current.setNode(qName);
        if (current.isEntryNode()) {
            if (!skip && hasPreviousVersion) {
                vulnerabilities.put(vulnerability, software);
            }
            vulnerability = null;
            software = null;
        }
    }

    // <editor-fold defaultstate="collapsed" desc="The Element Class that maintains state information about the current node">
    /**
     * A simple class to maintain information about the current element while
     * parsing the NVD CVE XML.
     */
    protected static class Element {

        /**
         * A node type in the NVD CVE Schema 1.2.
         */
        public static final String NVD = "nvd";
        /**
         * A node type in the NVD CVE Schema 1.2.
         */
        public static final String ENTRY = "entry";
        /**
         * A node type in the NVD CVE Schema 1.2.
         */
        public static final String VULN_SOFTWARE = "vuln_soft";
        /**
         * A node type in the NVD CVE Schema 1.2.
         */
        public static final String PROD = "prod";
        /**
         * A node type in the NVD CVE Schema 1.2.
         */
        public static final String VERS = "vers";
        /**
         * The name of the current node.
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
         * Checks if the handler is at the VULN_SOFTWARE node.
         *
         * @return true or false
         */
        public boolean isVulnSoftwareNode() {
            return VULN_SOFTWARE.equals(node);
        }

        /**
         * Checks if the handler is at the PROD node.
         *
         * @return true or false
         */
        public boolean isProdNode() {
            return PROD.equals(node);
        }

        /**
         * Checks if the handler is at the VERS node.
         *
         * @return true or false
         */
        public boolean isVersNode() {
            return VERS.equals(node);
        }
    }
    // </editor-fold>
}
