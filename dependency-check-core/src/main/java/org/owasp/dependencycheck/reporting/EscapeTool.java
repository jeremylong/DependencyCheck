/*
 * Copyright 2014 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.reporting;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang.StringEscapeUtils;

/**
 * An extremely simple wrapper around various escape utils to perform URL and HTML encoding within the reports. This
 * class was created to simplify the velocity configuration and avoid using the "built-in" escape tool.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class EscapeTool {

    /**
     * URL Encodes the provided text.
     *
     * @param text the text to encode
     * @return the URL encoded text
     */
    public String url(String text) {
        try {
            return URLEncoder.encode(text, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(EscapeTool.class.getName()).log(Level.WARNING, "UTF-8 is not supported?");
            Logger.getLogger(EscapeTool.class.getName()).log(Level.INFO, null, ex);
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
        return StringEscapeUtils.escapeHtml(text);
    }

    /**
     * XML Encodes the provided text.
     *
     * @param text the text to encode
     * @return the XML encoded text
     */
    public String xml(String text) {
        return StringEscapeUtils.escapeXml(text);
    }
}
