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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.reporting;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import org.apache.commons.lang3.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An extremely simple wrapper around various escape utils to perform URL and HTML encoding within the reports. This class was
 * created to simplify the velocity configuration and avoid using the "built-in" escape tool.
 *
 * @author Jeremy Long
 */
public class EscapeTool {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(EscapeTool.class);

    /**
     * URL Encodes the provided text.
     *
     * @param text the text to encode
     * @return the URL encoded text
     */
    public String url(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        try {
            return URLEncoder.encode(text, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            LOGGER.warn("UTF-8 is not supported?");
            LOGGER.info("", ex);
        }
        return "";
    }

    /**
     * HTML Encodes the provided text.
     *
     * @param text the text to encode
     * @return the HTML encoded text
     */
    public String html(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        return StringEscapeUtils.escapeHtml4(text);
    }

    /**
     * XML Encodes the provided text.
     *
     * @param text the text to encode
     * @return the XML encoded text
     */
    public String xml(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        return StringEscapeUtils.escapeXml11(text);
    }

    /**
     * JSON Encodes the provded text
     * @param text the text to encode
     * @return the JSON encoded text
     */
    public String json(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        return StringEscapeUtils.escapeJson(text);
    }
}
