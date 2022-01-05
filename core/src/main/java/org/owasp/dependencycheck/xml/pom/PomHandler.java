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
import javax.annotation.concurrent.NotThreadSafe;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A handler to read the pom.xml model.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
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
    public static final String LICENSE_NODE = "license";
    /**
     * The developers element.
     */
    public static final String DEVELOPERS = "developers";
    /**
     * The developer element.
     */
    public static final String DEVELOPER_NODE = "developer";
    /**
     * The developer id element.
     */
    public static final String DEVELOPER_ID = "id";
    /**
     * The developer email element.
     */
    public static final String DEVELOPER_EMAIL = "email";
    /**
     * The developer organization element.
     */
    public static final String DEVELOPER_ORGANIZATION = "organization";
    /**
     * The developer organization URL element.
     */
    public static final String DEVELOPER_ORGANIZATION_URL = "organizationUrl";
    /**
     * The URL element.
     */
    public static final String URL = "url";
    /**
     * The pom model.
     */
    private final Model model = new Model();
    /**
     * The stack of elements processed; used to determine the parent node.
     */
    private final Deque<String> stack = new ArrayDeque<>();
    /**
     * The license object.
     */
    private License license = null;
    /**
     * The developer object.
     */
    private Developer developer = null;
    /**
     * The current node text being extracted from the element.
     */
    private StringBuilder currentText;

    /**
     * Returns the model obtained from the pom.xml.
     *
     * @return the model object
     */
    public Model getModel() {
        return model;
    }

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
        stack.push(qName);
        if (LICENSE_NODE.equals(qName)) {
            license = new License();
        } else if (DEVELOPER_NODE.equals(qName)) {
            developer = new Developer();
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
        if (null != parentNode) {
            switch (parentNode) {
                case PROJECT:
                    if (null != qName) {
                        switch (qName) {
                            case GROUPID:
                                model.setGroupId(currentText.toString());
                                break;
                            case ARTIFACTID:
                                model.setArtifactId(currentText.toString());
                                break;
                            case VERSION:
                                model.setVersion(currentText.toString());
                                break;
                            case NAME:
                                model.setName(currentText.toString());
                                break;
                            case DESCRIPTION:
                                model.setDescription(currentText.toString());
                                break;
                            case URL:
                                model.setProjectURL(currentText.toString());
                                break;
                            default:
                                break;
                        }
                    }
                    break;
                case ORGANIZATION:
                    if (NAME.equals(qName)) {
                        model.setOrganization(currentText.toString());
                    } else if (URL.equals(qName)) {
                        model.setOrganizationUrl(currentText.toString());
                    }
                    break;
                case PARENT:
                    if (null != qName) {
                        switch (qName) {
                            case GROUPID:
                                model.setParentGroupId(currentText.toString());
                                break;
                            case ARTIFACTID:
                                model.setParentArtifactId(currentText.toString());
                                break;
                            case VERSION:
                                model.setParentVersion(currentText.toString());
                                break;
                            default:
                                break;
                        }
                    }
                    break;
                case LICENSE_NODE:
                    if (license != null) {
                        if (NAME.equals(qName)) {
                            license.setName(currentText.toString());
                        } else if (URL.equals(qName)) {
                            license.setUrl(currentText.toString());
                        }
                    }
                    break;
                case LICENSES:
                    if (LICENSE_NODE.equals(qName) && license != null) {
                        model.addLicense(license);
                        license = null;
                    }
                    break;
                case DEVELOPER_NODE:
                    if (developer != null && qName != null) {
                        switch (qName) {
                            case DEVELOPER_ID:
                                developer.setId(currentText.toString());
                                break;
                            case NAME:
                                developer.setName(currentText.toString());
                                break;
                            case DEVELOPER_EMAIL:
                                developer.setEmail(currentText.toString());
                                break;
                            case DEVELOPER_ORGANIZATION:
                                developer.setOrganization(currentText.toString());
                                break;
                            case DEVELOPER_ORGANIZATION_URL:
                                developer.setOrganizationUrl(currentText.toString());
                                break;
                            default:
                                break;
                        }
                    }
                    break;
                case DEVELOPERS:
                    if (DEVELOPER_NODE.equals(qName) && developer != null) {
                        model.addDeveloper(developer);
                        developer = null;
                    }
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
}
