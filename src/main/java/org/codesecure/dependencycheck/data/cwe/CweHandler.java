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
package org.codesecure.dependencycheck.data.cwe;

import java.util.HashMap;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A SAX Handler that will parse the CWE XML.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class CweHandler extends DefaultHandler {

    private HashMap<String, String> cwe = new HashMap<String, String>();

    /**
     * Returns the HashMap of CWE entries (CWE-ID, Full CWE Name).
     * @return a HashMap of CWE entries <String, String>
     */
    public HashMap<String, String> getCwe() {
        return cwe;
    }

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {

        if ("Weakness".equals(qName) || "Category".equals(qName)) {
            String id = "CWE-" + attributes.getValue("ID");
            String name = attributes.getValue("Name");
            cwe.put(id, name);
        }
    }
}
