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
 * Copyright (c) 2019 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.assembly;

import javax.annotation.concurrent.NotThreadSafe;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A handler to read Grok Assembly XML files.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class GrokHandler extends DefaultHandler {

    /**
     * An XML node name.
     */
    private static final String ERROR = "error";
    /**
     * An XML node name.
     */
    private static final String WARNING = "warning";
    /**
     * An XML node name.
     */
    private static final String COMPANY_NAME = "companyName";
    /**
     * An XML node name.
     */
    private static final String PRODUCT_NAME = "productName";
    /**
     * An XML node name.
     */
    private static final String PRODUCT_VERSION = "productVersion";
    /**
     * An XML node name.
     */
    private static final String COMMENTS = "comments";
    /**
     * An XML node name.
     */
    private static final String FILE_DESCRIPTION = "fileDescription";
    /**
     * An XML node name.
     */
    private static final String FILE_NAME = "fileName";
    /**
     * An XML node name.
     */
    private static final String FILE_VERSION = "fileVersion";
    /**
     * An XML node name.
     */
    private static final String INTERNAL_NAME = "internalName";
    /**
     * An XML node name.
     */
    private static final String ORIGINAL_FILE_NAME = "originalFilename";
    /**
     * An XML node name.
     */
    private static final String FULLNAME = "fullName";
    /**
     * An XML node name.
     */
    private static final String NAMESPACE = "namespace";

    /**
     * The current rule being read.
     */
    private final AssemblyData data = new AssemblyData();
    /**
     * The current node text being extracted from the element.
     */
    private StringBuilder currentText;

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
        currentText = new StringBuilder();
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
                case COMPANY_NAME:
                    data.setCompanyName(currentText.toString());
                    break;
                case PRODUCT_NAME:
                    data.setProductName(currentText.toString());
                    break;
                case PRODUCT_VERSION:
                    data.setProductVersion(currentText.toString());
                    break;
                case COMMENTS:
                    data.setComments(currentText.toString());
                    break;
                case FILE_DESCRIPTION:
                    data.setFileDescription(currentText.toString());
                    break;
                case FILE_NAME:
                    data.setFileName(currentText.toString());
                    break;
                case FILE_VERSION:
                    data.setFileVersion(currentText.toString());
                    break;
                case INTERNAL_NAME:
                    data.setInternalName(currentText.toString());
                    break;
                case ORIGINAL_FILE_NAME:
                    data.setOriginalFilename(currentText.toString());
                    break;
                case FULLNAME:
                    data.setFullName(currentText.toString());
                    break;
                case NAMESPACE:
                    data.addNamespace(currentText.toString());
                    break;
                case ERROR:
                    data.setError(currentText.toString());
                    break;
                case WARNING:
                    data.setWarning(currentText.toString());
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

    AssemblyData getAssemblyData() {
        return data;
    }
}
