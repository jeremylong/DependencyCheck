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
package org.owasp.dependencycheck.xml.pom;

import java.util.ArrayDeque;
import java.util.Deque;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A handler to read the pom.xml model.
 *
 * @author Jeremy Long
 */
public class PomHandler extends DefaultHandler {

    /**
     * The project element.
     */
    public static final String PROJECT = "project";
    /**
     * The artifactId element.
     */
    public static final String GROUPID = "groupId";
    /**
     * The artifactId element.
     */
    public static final String ARTIFACTID = "artifactId";
    /**
     * The version element.
     */
    public static final String VERSION = "version";
    /**
     * The parent element.
     */
    public static final String PARENT = "parent";
    /**
     * The name element.
     */
    public static final String NAME = "name";
    /**
     * The organization element.
     */
    public static final String ORGANIZATION = "organization";
    /**
     * The description element.
     */
    public static final String DESCRIPTION = "description";
    /**
     * The licenses element.
     */
    public static final String LICENSES = "licenses";
    /**
     * The license element.
     */
    public static final String LICENSE = "license";
    /**
     * The url element.
     */
    public static final String URL = "url";

    /**
     * The pom model.
     */
    private Model model = new Model();

    /**
     * Returns the model obtained from the pom.xml.
     *
     * @return the model object
     */
    public Model getModel() {
        return model;
    }
    /**
     * The stack of elements processed; used to determine the parent node.
     */
    private final Deque<String> stack = new ArrayDeque<String>();
    /**
     * The license object.
     */
    private License license = null;

    /**
     * The current node text being extracted from the element.
     */
    private StringBuffer currentText;

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
        currentText = new StringBuffer();
        stack.push(qName);
        if (LICENSE.equals(qName)) {
            license = new License();
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
        stack.pop();
        final String parentNode = stack.peek();
        if (PROJECT.equals(parentNode)) {
            if (GROUPID.equals(qName)) {
                model.setGroupId(currentText.toString());
            } else if (ARTIFACTID.equals(qName)) {
                model.setArtifactId(currentText.toString());
            } else if (VERSION.equals(qName)) {
                model.setVersion(currentText.toString());
            } else if (NAME.equals(qName)) {
                model.setName(currentText.toString());
            } else if (ORGANIZATION.equals(qName)) {
                model.setOrganization(currentText.toString());
            } else if (DESCRIPTION.equals(qName)) {
                model.setDescription(currentText.toString());
            }
        } else if (PARENT.equals(parentNode)) {
            if (GROUPID.equals(qName)) {
                model.setParentGroupId(currentText.toString());
            } else if (ARTIFACTID.equals(qName)) {
                model.setParentArtifactId(currentText.toString());
            } else if (VERSION.equals(qName)) {
                model.setParentVersion(currentText.toString());
            }
        } else if (LICENSE.equals(parentNode)) {
            if (license != null) {
                if (NAME.equals(qName)) {
                    license.setName(currentText.toString());
                } else if (URL.equals(qName)) {
                    license.setUrl(currentText.toString());
                }
                //} else {
                //TODO add error logging
            }
        } else if (LICENSES.equals(parentNode)) {
            if (LICENSE.equals(qName)) {
                if (license != null) {
                    model.addLicense(license);
                    //} else {
                    //TODO add error logging
                }
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
}
