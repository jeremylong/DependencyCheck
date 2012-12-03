package org.codesecure.dependencycheck.data.cpe.xml;
/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.text.ParseException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.index.CorruptIndexException;
import org.codesecure.dependencycheck.data.cpe.Entry;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A SAX Handler that will parse the CPE XML Listing.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class CPEHandler extends DefaultHandler {

    private static final String CURRENT_SCHEMA_VERSION = "2.2";
    EntrySaveDelegate saveDelegate = null;
    Entry entry = null;
    boolean languageIsUS = false;
    StringBuilder nodeText = null;
    boolean skip = false;
    Element current = new Element();

    /**
     * Register a EntrySaveDelegate object. When the last node of an entry is
     * reached if a save delegate has been registered the save method will be
     * invoked.
     *
     * @param delegate the delegate used to save an entry
     */
    public void registerSaveDelegate(EntrySaveDelegate delegate) {
        this.saveDelegate = delegate;
    }

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
        nodeText = null;
        current.setNode(qName);
        if (current.isCpeItemNode()) {
            entry = new Entry();
            String temp = attributes.getValue("deprecated");
            String name = attributes.getValue("name");
            skip = (temp != null && temp.equals("true"));
            try {
                if (!skip && name.startsWith("cpe:/a:")) {
                    entry.parseName(name);
                } else {
                    skip = true;
                }
            } catch (UnsupportedEncodingException ex) {
                throw new SAXException(ex);
            }
        } else if (current.isTitleNode()) {
            nodeText = new StringBuilder(100);
            if ("en-US".equalsIgnoreCase(attributes.getValue("xml:lang"))) {
                languageIsUS = true;
            } else {
                languageIsUS = false;
            }
        } else if (current.isMetaNode()) {
            try {
                entry.setModificationDate(attributes.getValue("modification-date"));
            } catch (ParseException ex) {
                Logger.getLogger(CPEHandler.class.getName()).log(Level.SEVERE, null, ex);
            }
            entry.setStatus(attributes.getValue("status"));
            entry.setNvdId(attributes.getValue("nvd-id"));
        } else if (current.isSchemaVersionNode()) {
            nodeText = new StringBuilder(3);
        } else if (current.isTimestampNode()) {
            nodeText = new StringBuilder(24);
        }
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

    @Override
    public void characters(char[] ch, int start, int length) throws SAXException {
        //nodeText += new String(ch, start, length);
        if (nodeText != null) {
            nodeText.append(ch, start, length);
        }
    }

    @Override
    public void endElement(String uri, String localName, String qName) throws SAXException {
        current.setNode(qName);
        if (current.isCpeItemNode()) {
            if (saveDelegate != null && !skip) {
                try {
                    saveDelegate.saveEntry(entry);
                } catch (CorruptIndexException ex) {
                    Logger.getLogger(CPEHandler.class.getName()).log(Level.SEVERE, null, ex);
                    throw new SAXException(ex);
                } catch (IOException ex) {
                    Logger.getLogger(CPEHandler.class.getName()).log(Level.SEVERE, null, ex);
                    throw new SAXException(ex);
                }
                entry = null;
            }
        } else if (current.isTitleNode()) {
            if (languageIsUS) {
                entry.setTitle(nodeText.toString());
            }
        } else if (current.isSchemaVersionNode() && !CURRENT_SCHEMA_VERSION.equals(nodeText.toString())) {
            throw new SAXException("ERROR: Invalid Schema Version, expected: "
                    + CURRENT_SCHEMA_VERSION + ", file is: " + nodeText);
        }
//        } else if (current.isCpeListNode()) {
//            //do nothing
//        } else if (current.isMetaNode()) {
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
//        else if (current.isTimestampNode()) {
//            //do nothing
//        } else {
//            throw new SAXException("ERROR STATE: Unexpected qName '" + qName + "'");
//        }
    }

    // <editor-fold defaultstate="collapsed" desc="The Element Class that maintains state information about the current node">
    /**
     * A simple class to maintain information about the current element while
     * parsing the CPE XML.
     */
    protected class Element {

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
