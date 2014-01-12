/*
 * This file is part of dependency-check-core.
 *
 * Dependency-check-core is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-check-core is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * dependency-check-core. If not, see http://www.gnu.org/licenses/.
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
        Logger.getLogger(SuppressionErrorHandler.class.getName()).log(Level.FINE, null, ex);
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
