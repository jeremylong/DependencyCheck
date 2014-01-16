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
package org.owasp.dependencycheck.utils;

import java.util.logging.Filter;
import java.util.logging.LogRecord;

/**
 * A simple log filter to limit the entries written to the verbose log file. The verbose log file uses the root logger
 * as I couldn't get anything else to work; as such, this filter limits the log entries to specific classes.
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
