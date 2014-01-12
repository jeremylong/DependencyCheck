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
package org.owasp.dependencycheck.jaxb.pom;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.XMLFilterImpl;

/**
 * This filter is used when parsing POM documents. Some POM documents do not
 * specify the xmlns="http://maven.apache.org/POM/4.0.0". This filter ensures
 * that the correct namespace is added so that both types of POMs can be read.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class MavenNamespaceFilter extends XMLFilterImpl {

    /**
     * The namespace to add for Maven POMs.
     */
    private static final String NAMESPACE = "http://maven.apache.org/POM/4.0.0";
    /**
     * A flag indicating whether or not the namespace (prefix) has been added.
     */
    private boolean namespaceAdded = false;

    /**
     * Called at the start of the document parsing.
     *
     * @throws SAXException thrown if there is a SAXException
     */
    @Override
    public void startDocument() throws SAXException {
        super.startDocument();
        startPrefixMapping("", NAMESPACE);
    }

    /**
     * Called when an element is started.
     *
     * @param uri the uri
     * @param localName the localName
     * @param qName the qualified name
     * @param atts the attributes
     * @throws SAXException thrown if there is a SAXException
     */
    @Override
    public void startElement(String uri, String localName, String qName, Attributes atts) throws SAXException {
        super.startElement(NAMESPACE, localName, qName, atts);
    }

    /**
     * Indicatees the start of the document.
     *
     * @param uri the uri
     * @param localName the localName
     * @param qName the qualified name
     * @throws SAXException thrown if there is a SAXException
     */
    @Override
    public void endElement(String uri, String localName, String qName)
            throws SAXException {
        super.endElement(NAMESPACE, localName, qName);
    }

    /**
     * Called when prefix mapping is started.
     *
     * @param prefix the prefix
     * @param url the url
     * @throws SAXException thrown if there is a SAXException
     */
    @Override
    public void startPrefixMapping(String prefix, String url) throws SAXException {
        if (!this.namespaceAdded) {
            namespaceAdded = true;
            super.startPrefixMapping("", NAMESPACE);
        }
    }
}
