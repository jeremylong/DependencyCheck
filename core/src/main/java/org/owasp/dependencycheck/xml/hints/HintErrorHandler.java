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
 * Copyright (c) 2016 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.xml.hints;

import javax.annotation.concurrent.ThreadSafe;
import org.owasp.dependencycheck.utils.XmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * An XML parsing error handler.
 *
 * @author Jeremy Long
 */
@ThreadSafe
public class HintErrorHandler implements ErrorHandler {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(HintErrorHandler.class);

    /**
     * Logs warnings.
     *
     * @param ex the warning to log
     * @throws SAXException is never thrown
     */
    @Override
    public void warning(SAXParseException ex) throws SAXException {
        LOGGER.debug("", ex);
    }

    /**
     * Handles errors.
     *
     * @param ex the error to handle
     * @throws SAXException is always thrown
     */
    @Override
    public void error(SAXParseException ex) throws SAXException {
        throw new SAXException(XmlUtils.getPrettyParseExceptionInfo(ex));
    }

    /**
     * Handles fatal exceptions.
     *
     * @param ex a fatal exception
     * @throws SAXException is always
     */
    @Override
    public void fatalError(SAXParseException ex) throws SAXException {
        throw new SAXException(XmlUtils.getPrettyParseExceptionInfo(ex));
    }
}
