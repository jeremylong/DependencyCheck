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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.suppression;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * An XML parsing error handler.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class SuppressionErrorHandler implements ErrorHandler {
    
    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(SuppressionErrorHandler.class.getName());
    /**
     * Builds a prettier exception message.
     *
     * @param ex the SAXParseException
     * @return an easier to read exception message
     */
    private String getPrettyParseExceptionInfo(SAXParseException ex) {

        final StringBuilder sb = new StringBuilder();

        if (ex.getSystemId() != null) {
            sb.append("systemId=").append(ex.getSystemId()).append(", ");
        }
        if (ex.getPublicId() != null) {
            sb.append("publicId=").append(ex.getPublicId()).append(", ");
        }
        if (ex.getLineNumber() > 0) {
            sb.append("Line=").append(ex.getLineNumber());
        }
        if (ex.getColumnNumber() > 0) {
            sb.append(", Column=").append(ex.getColumnNumber());
        }
        sb.append(": ").append(ex.getMessage());

        return sb.toString();
    }

    /**
     * Logs warnings.
     *
     * @param ex the warning to log
     * @throws SAXException is never thrown
     */
    @Override
    public void warning(SAXParseException ex) throws SAXException {
        LOGGER.log(Level.FINE, null, ex);
    }

    /**
     * Handles errors.
     *
     * @param ex the error to handle
     * @throws SAXException is always thrown
     */
    @Override
    public void error(SAXParseException ex) throws SAXException {
        throw new SAXException(getPrettyParseExceptionInfo(ex));
    }

    /**
     * Handles fatal exceptions.
     *
     * @param ex a fatal exception
     * @throws SAXException is always
     */
    @Override
    public void fatalError(SAXParseException ex) throws SAXException {
        throw new SAXException(getPrettyParseExceptionInfo(ex));
    }
}
