package org.codesecure.dependencycheck.data.nvdcve.xml;
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
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.UnmarshallerHandler;
import org.apache.lucene.index.CorruptIndexException;
import org.codesecure.dependencycheck.data.nvdcve.generated.VulnerabilityType;
import org.xml.sax.Attributes;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.NamespaceSupport;
import org.xml.sax.helpers.XMLFilterImpl;

/**
 *
 * <p>This filter uses partial-unmarshalling to unmarshall single NVD CVE
 * entries for use with a SAX Parser.</p>
 *
 * <p>This code was based off of an example found on <a
 * href="http://stackoverflow.com/questions/6484681/jaxb-partial-unmarshalling-elements-without-xmlrootelement">stackoverflow</a></p>
 *
 * @author Jeremy
 */
@Deprecated
public class NvdCveXmlFilter extends XMLFilterImpl {

    EntrySaveDelegate saveDelegate = null;

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
    /**
     * The JAXBContext
     */
    private final JAXBContext context;

    /**
     * Constructs a new NvdCveXmlFilter
     *
     * @param context a JAXBContext
     */
    public NvdCveXmlFilter(JAXBContext context) {
        this.context = context;
    }
    /**
     * The locator object used for unmarshalling
     */
    private Locator locator = null;

    /**
     * Sets the document locator.
     *
     * @param loc the locator to use.
     */
    @Override
    public void setDocumentLocator(Locator loc) {
        this.locator = loc;
        super.setDocumentLocator(loc);
    }
    /**
     * Used to keep track of namespace bindings.
     */
    private NamespaceSupport nsSupport = new NamespaceSupport();

    /**
     * Stores the namespace prefix for use during unmarshalling.
     *
     * @param prefix the namespace prefix.
     * @param uri the namespace.
     * @throws SAXException is thrown is there is a SAXException.
     */
    @Override
    public void startPrefixMapping(String prefix, String uri) throws SAXException {
        nsSupport.pushContext();
        nsSupport.declarePrefix(prefix, uri);
        super.startPrefixMapping(prefix, uri);
    }

    /**
     * Removes the namespace prefix from the local support object so that
     * unmarshalling works correctly.
     *
     * @param prefix the prefix to remove.
     * @throws SAXException is thrown is there is a SAXException.
     */
    @Override
    public void endPrefixMapping(String prefix) throws SAXException {
        nsSupport.popContext();
        super.endPrefixMapping(prefix);
    }
    /**
     * The UnmarshallerHandler.
     */
    private UnmarshallerHandler unmarshallerHandler;
    /**
     * Used to track how deep the SAX parser is in nested XML.
     */
    private int depth;

    /**
     * Fired when the SAX parser starts an element. This will either forward the
     * event to the unmarshaller or create an unmarshaller if it is at the start
     * of a new "entry".
     *
     * @param uri uri
     * @param localName localName
     * @param qName qName
     * @param atts atts
     * @throws SAXException is thrown if there is a SAXException.
     */
    @Override
    public void startElement(String uri, String localName, String qName, Attributes atts) throws SAXException {

        if (depth != 0) {
            // we are in the middle of forwarding events.
            // continue to do so.
            depth += 1;
            super.startElement(uri, localName, qName, atts);
            return;
        }

        //old - for cve 1.2 uri.equals("http://nvd.nist.gov/feeds/cve/1.2")
        if (uri.equals("http://scap.nist.gov/schema/feed/vulnerability/2.0") && localName.equals("entry")) {
            Unmarshaller unmarshaller;
            try {
                unmarshaller = context.createUnmarshaller();
            } catch (JAXBException e) {
                throw new SAXException(e);
            }
            unmarshallerHandler = unmarshaller.getUnmarshallerHandler();
            setContentHandler(unmarshallerHandler);

            // fire SAX events to emulate the start of a new document.
            unmarshallerHandler.startDocument();
            unmarshallerHandler.setDocumentLocator(locator);

            Enumeration e = nsSupport.getPrefixes();
            while (e.hasMoreElements()) {
                String prefix = (String) e.nextElement();
                String uriToUse = nsSupport.getURI(prefix);

                unmarshallerHandler.startPrefixMapping(prefix, uriToUse);
            }
            String defaultURI = nsSupport.getURI("");
            if (defaultURI != null) {
                unmarshallerHandler.startPrefixMapping("", defaultURI);
            }

            super.startElement(uri, localName, qName, atts);

            // count the depth of elements and we will know when to stop.
            depth = 1;
        }
    }

    /**
     * Processes the end of an element. If we are at depth 0 we unmarshall the
     * Entry and pass it to the save delegate
     *
     * @param uri the uri of the current element
     * @param localName the local name of the current element
     * @param qName the qname of the current element
     * @throws SAXException is thrown if there is a SAXException
     */
    @Override
    public void endElement(String uri, String localName, String qName) throws SAXException {

        // forward this event
        super.endElement(uri, localName, qName);

        if (depth != 0) {
            depth -= 1;
            if (depth == 0) {

                // emulate the end of a document.
                Enumeration e = nsSupport.getPrefixes();
                while (e.hasMoreElements()) {
                    String prefix = (String) e.nextElement();
                    unmarshallerHandler.endPrefixMapping(prefix);
                }
                String defaultURI = nsSupport.getURI("");
                if (defaultURI != null) {
                    unmarshallerHandler.endPrefixMapping("");
                }
                unmarshallerHandler.endDocument();

                // stop forwarding events by setting a dummy handler.
                // XMLFilter doesn't accept null, so we have to give it something,
                // hence a DefaultHandler, which does nothing.
                setContentHandler(new DefaultHandler());

                // then retrieve the fully unmarshalled object
                try {
                    if (saveDelegate != null) {
                        JAXBElement<VulnerabilityType> result = (JAXBElement<VulnerabilityType>) unmarshallerHandler.getResult();
                        VulnerabilityType entry = result.getValue();
                        saveDelegate.saveEntry(entry);
                    }
                } catch (JAXBException je) { //we can continue with this exception.
                    //TODO can I get the filename somewhere?
                    Logger.getLogger(NvdCveXmlFilter.class.getName()).log(Level.SEVERE,
                            "Unable to unmarshall NvdCVE (line " + locator.getLineNumber() + ").", je);
                } catch (CorruptIndexException ex) {
                    Logger.getLogger(NvdCveXmlFilter.class.getName()).log(Level.SEVERE, null, ex);
                    throw new SAXException(ex);
                } catch (IOException ex) {
                    Logger.getLogger(NvdCveXmlFilter.class.getName()).log(Level.SEVERE, null, ex);
                    throw new SAXException(ex);
                } finally {
                    unmarshallerHandler = null;
                }
            }
        }
    }
}
