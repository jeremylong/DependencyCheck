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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.cwe;

import java.util.HashMap;
import javax.annotation.concurrent.NotThreadSafe;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * A SAX Handler that will parse the CWE XML.
 *
 * @author Jeremy Long
 */
@NotThreadSafe
public class CweHandler extends DefaultHandler {

    /**
     * a HashMap containing the CWE data.
     */
    private final HashMap<String, String> cwe = new HashMap<>();

    /**
     * Returns the HashMap of CWE entries (CWE-ID, Full CWE Name).
     *
     * @return a HashMap of CWE entries &lt;String, String&gt;
     */
    public HashMap<String, String> getCwe() {
        return cwe;
    }

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {

        if ("Weakness".equals(qName) || "Category".equals(qName)) {
            final String id = "CWE-" + attributes.getValue("ID");
            final String name = attributes.getValue("Name");
            cwe.put(id, name);
        }
    }
}
