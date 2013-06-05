/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.owasp.dependencycheck.analyzer.pom;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.XMLFilterImpl;

/**
 * This filter is used when parsing POM documents. Some POM documents
 * do not specify the xmlns="http://maven.apache.org/POM/4.0.0". This
 * filter ensures that the correct namespace is added so that both
 * types of POMs can be read.
 * @author Jeremy Long (jeremy.long@gmail.com)
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
     * @throws SAXException thrown if there is a SAXException
     */
    @Override
    public void startDocument() throws SAXException {
        super.startDocument();
        startPrefixMapping("", NAMESPACE);
    }

    /**
     * Called when an element is started.
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
     * Called when prefix mapping
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
