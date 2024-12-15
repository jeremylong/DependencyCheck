/*
 * This file is part of dependency-check-utils.
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
 * Copyright (c) 2024 Hans Aikema. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.apache.hc.client5.http.impl.classic.AbstractHttpClientResponseHandler;
import org.apache.hc.core5.http.HttpEntity;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.InputStream;

public class ToXMLDocumentResponseHandler extends AbstractHttpClientResponseHandler<Document> {
    @Override
    public Document handleEntity(HttpEntity entity) throws IOException {
        try (InputStream in = entity.getContent()) {
            final DocumentBuilder builder = XmlUtils.buildSecureDocumentBuilder();
            return builder.parse(in);
        } catch (ParserConfigurationException | SAXException | IOException e) {
            final String errorMessage = "Failed to parse XML Response: " + e.getMessage();
            throw new IOException(errorMessage, e);
        }
    }
}
