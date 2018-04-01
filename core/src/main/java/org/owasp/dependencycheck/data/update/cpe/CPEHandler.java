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
 * Copyright (c) 2015 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.cpe;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.concurrent.NotThreadSafe;
import org.owasp.dependencycheck.data.update.exception.InvalidDataException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A SAX Handler that will parse the CPE XML and load it into the database.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class CPEHandler extends DefaultHandler {

    /**
     * The current CPE schema.
     */
    private static final String CURRENT_SCHEMA_VERSION = "2.3";
    /**
     * The Starts with expression to filter CVE entries by CPE.
     */
    private final String cpeStartsWith;
    /**
     * The text content of the node being processed. This can be used during the
     * end element event.
     */
    private StringBuilder nodeText = null;
    /**
     * A reference to the current element.
     */
    private final Element current = new Element();
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CPEHandler.class);
    /**
     * The list of CPE values.
     */
    private final List<Cpe> data = new ArrayList<>();

    /**
     * Constructs a new CPE Handler object with the configured settings.
     *
     * @param settings the configured settings
     */
    public CPEHandler(Settings settings) {
        cpeStartsWith = settings.getString(Settings.KEYS.CVE_CPE_STARTS_WITH_FILTER, "cpe:/a:");
    }

    /**
     * Returns the list of CPE values.
     *
     * @return the list of CPE values
     */
    public List<Cpe> getData() {
        return data;
    }

    /**
     * Handles the start element event.
     *
     * @param uri the elements uri
     * @param localName the local name
     * @param qName the qualified name
     * @param attributes the attributes
     * @throws SAXException thrown if there is an exception processing the
     * element
     */
    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
        nodeText = null;
        current.setNode(qName);
        if (current.isCpeItemNode()) {
            final String temp = attributes.getValue("deprecated");
            final String value = attributes.getValue("name");
            final boolean delete = "true".equalsIgnoreCase(temp);
            if (!delete && value.startsWith(cpeStartsWith) && value.length() > 7) {
                try {
                    final Cpe cpe = new Cpe(value);
                    data.add(cpe);
                } catch (UnsupportedEncodingException ex) {
                    LOGGER.debug("Unable to parse the CPE", ex);
                } catch (InvalidDataException ex) {
                    LOGGER.debug("CPE is not the correct format", ex);
                }
            }
        } else if (current.isSchemaVersionNode()) {
            nodeText = new StringBuilder(3);
        }
//        } else if (current.isTitleNode()) {
//            //do nothing
//        } else if (current.isMetaNode()) {
//            //do nothing
//        } else if (current.isTimestampNode()) {
//            //do nothing
//        } else if (current.isCpeListNode()) {
//            //do nothing
//        } else if (current.isNotesNode()) {
//            //do nothing
//        } else if (current.isNoteNode()) {
//            //do nothing
//        } else if (current.isCheckNode()) {
//            //do nothing
//        } else if (current.isGeneratorNode()) {
//            //do nothing
//        } else if (current.isProductNameNode()) {
//            //do nothing
//        } else if (current.isProductVersionNode()) {
//            //do nothing
    }

    /**
     * Reads the characters in the current node.
     *
     * @param ch the char array
     * @param start the start position of the data read
     * @param length the length of the data read
     * @throws SAXException thrown if there is an exception processing the
     * characters
     */
    @Override
    public void characters(char[] ch, int start, int length) throws SAXException {
        if (nodeText != null) {
            nodeText.append(ch, start, length);
        }
    }

    /**
     * Handles the end element event. Stores the CPE data in the Cve Database if
     * the cpe item node is ending.
     *
     * @param uri the element's uri
     * @param localName the local name
     * @param qName the qualified name
     * @throws SAXException thrown if there is an exception processing the
     * element
     */
    @Override
    public void endElement(String uri, String localName, String qName) throws SAXException {
        current.setNode(qName);
        if (current.isSchemaVersionNode() && !CURRENT_SCHEMA_VERSION.equals(nodeText.toString())) {
            throw new SAXException("ERROR: Unexpected CPE Schema Version, expected: "
                    + CURRENT_SCHEMA_VERSION + ", file is: " + nodeText);

        }
    }

    // <editor-fold defaultstate="collapsed" desc="The Element Class that maintains state information about the current node">
    /**
     * A simple class to maintain information about the current element while
     * parsing the CPE XML.
     */
    protected static final class Element {

        /**
         * A node type in the CPE Schema 2.2
         */
        public static final String CPE_LIST = "cpe-list";
        /**
         * A node type in the CPE Schema 2.2
         */
        public static final String CPE_ITEM = "cpe-item";
        /**
         * A node type in the CPE Schema 2.2
         */
        public static final String TITLE = "title";
        /**
         * A node type in the CPE Schema 2.2
         */
        public static final String NOTES = "notes";
        /**
         * A node type in the CPE Schema 2.2
         */
        public static final String NOTE = "note";
        /**
         * A node type in the CPE Schema 2.2
         */
        public static final String CHECK = "check";
        /**
         * A node type in the CPE Schema 2.2
         */
        public static final String META = "meta:item-metadata";
        /**
         * A node type in the CPE Schema 2.2
         */
        public static final String GENERATOR = "generator";
        /**
         * A node type in the CPE Schema 2.2
         */
        public static final String PRODUCT_NAME = "product_name";
        /**
         * A node type in the CPE Schema 2.2
         */
        public static final String PRODUCT_VERSION = "product_version";
        /**
         * A node type in the CPE Schema 2.2
         */
        public static final String SCHEMA_VERSION = "schema_version";
        /**
         * A node type in the CPE Schema 2.2
         */
        public static final String TIMESTAMP = "timestamp";
        /**
         * A reference to the current node.
         */
        private String node = null;

        /**
         * Gets the value of node
         *
         * @return the value of node
         */
        public String getNode() {
            return this.node;
        }

        /**
         * Sets the value of node
         *
         * @param node new value of node
         */
        public void setNode(String node) {
            this.node = node;
        }

        /**
         * Checks if the handler is at the CPE_LIST node
         *
         * @return true or false
         */
        public boolean isCpeListNode() {
            return CPE_LIST.equals(node);
        }

        /**
         * Checks if the handler is at the CPE_ITEM node
         *
         * @return true or false
         */
        public boolean isCpeItemNode() {
            return CPE_ITEM.equals(node);
        }

        /**
         * Checks if the handler is at the TITLE node
         *
         * @return true or false
         */
        public boolean isTitleNode() {
            return TITLE.equals(node);
        }

        /**
         * Checks if the handler is at the NOTES node
         *
         * @return true or false
         */
        public boolean isNotesNode() {
            return NOTES.equals(node);
        }

        /**
         * Checks if the handler is at the NOTE node
         *
         * @return true or false
         */
        public boolean isNoteNode() {
            return NOTE.equals(node);
        }

        /**
         * Checks if the handler is at the CHECK node
         *
         * @return true or false
         */
        public boolean isCheckNode() {
            return CHECK.equals(node);
        }

        /**
         * Checks if the handler is at the META node
         *
         * @return true or false
         */
        public boolean isMetaNode() {
            return META.equals(node);
        }

        /**
         * Checks if the handler is at the GENERATOR node
         *
         * @return true or false
         */
        public boolean isGeneratorNode() {
            return GENERATOR.equals(node);
        }

        /**
         * Checks if the handler is at the PRODUCT_NAME node
         *
         * @return true or false
         */
        public boolean isProductNameNode() {
            return PRODUCT_NAME.equals(node);
        }

        /**
         * Checks if the handler is at the PRODUCT_VERSION node
         *
         * @return true or false
         */
        public boolean isProductVersionNode() {
            return PRODUCT_VERSION.equals(node);
        }

        /**
         * Checks if the handler is at the SCHEMA_VERSION node
         *
         * @return true or false
         */
        public boolean isSchemaVersionNode() {
            return SCHEMA_VERSION.equals(node);
        }

        /**
         * Checks if the handler is at the TIMESTAMP node
         *
         * @return true or false
         */
        public boolean isTimestampNode() {
            return TIMESTAMP.equals(node);
        }
    }
    // </editor-fold>
}
