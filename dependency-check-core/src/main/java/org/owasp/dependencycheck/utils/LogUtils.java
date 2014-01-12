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
            Logger.getLogger(LogUtils.class.getName()).log(Level.FINE, "IO Error preparing the logger", ex);
        } catch (SecurityException ex) {
            Logger.getLogger(LogUtils.class.getName()).log(Level.FINE, "Error preparing the logger", ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Exception ex) {
                    Logger.getLogger(LogUtils.class.getName()).log(Level.FINEST, "Error closing resource stream", ex);
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
