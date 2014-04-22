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
package org.owasp.dependencycheck.jaxb.pom;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.XMLFilterImpl;

/**
 * This filter is used when parsing POM documents. Some POM documents do not specify the
 * xmlns="http://maven.apache.org/POM/4.0.0". This filter ensures that the correct namespace is added so that both types
 * of POMs can be read.
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
     * @param attributes the attributes
     * @throws SAXException thrown if there is a SAXException
     */
    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
        super.startElement(NAMESPACE, localName, qName, attributes);
    }

    /**
     * Indicates the start of the document.
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
