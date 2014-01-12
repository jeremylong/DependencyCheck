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
package org.owasp.dependencycheck.utils;

import java.util.logging.Filter;
import java.util.logging.LogRecord;

/**
 * A simple log filter to limit the entries written to the verbose log file. The
 * verbose log file uses the root logger as I couldn't get anything else to
 * work; as such, this filter limits the log entries to specific classes.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class LogFilter implements Filter {

    /**
     * Determines if the record should be logged.
     *
     * @param record a log record to examine
     * @return true if the record should be logged, otherwise false
     */
    @Override
    public boolean isLoggable(LogRecord record) {
        final String name = record.getSourceClassName();
        return name.startsWith("org.owasp.dependencycheck") && !name.contains("generated") && !name.contains("VelocityLoggerRedirect");
    }
}
