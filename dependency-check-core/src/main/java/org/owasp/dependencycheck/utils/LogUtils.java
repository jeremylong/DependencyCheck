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

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * A utility class to aide in the setup of the logging mechanism.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public final class LogUtils {
    
    /**
     * The logger.
     */
    private static final Logger LOGGER = Logger.getLogger(LogUtils.class.getName());
    /**
     * Private constructor for a utility class.
     */
    private LogUtils() {
    }

    /**
     * Configures the logger for use by the application.
     *
     * @param in the input stream to read the log settings from
     * @param verboseLogFile the file path for the verbose log
     */
    public static void prepareLogger(InputStream in, String verboseLogFile) {
        try {
            LogManager.getLogManager().reset();
            LogManager.getLogManager().readConfiguration(in);
            if (verboseLogFile != null && !verboseLogFile.isEmpty()) {
                verboseLoggingEnabled = true;
                final Logger logger = Logger.getLogger("");
                final FileHandler handler = new FileHandler(verboseLogFile, true);
                handler.setFormatter(new SimpleFormatter());
                handler.setLevel(Level.FINE);
                handler.setFilter(new LogFilter());
                logger.addHandler(handler);
                logger.setLevel(Level.FINE);
            }
        } catch (IOException ex) {
            LOGGER.log(Level.FINE, "IO Error preparing the logger", ex);
        } catch (SecurityException ex) {
            LOGGER.log(Level.FINE, "Error preparing the logger", ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ex) {
                    LOGGER.log(Level.FINEST, "Error closing resource stream", ex);
                }
            }
        }
    }
    /**
     * Whether or not verbose logging is enabled.
     */
    private static boolean verboseLoggingEnabled = false;

    /**
     * Get the value of verboseLoggingEnabled.
     *
     * @return the value of verboseLoggingEnabled
     */
    public static boolean isVerboseLoggingEnabled() {
        return verboseLoggingEnabled;
    }
}
