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
 * Copyright (c) 2013 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.reporting;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.runtime.RuntimeServices;
import org.apache.velocity.runtime.log.LogChute;

/**
 * <p>
 * DependencyCheck uses {@link java.util.logging.Logger} as a logging framework, and Apache Velocity uses a custom
 * logging implementation that outputs to a file named velocity.log by default. This class is an implementation of a
 * custom Velocity logger that redirects all velocity logging to the Java Logger class.
 * </p><p>
 * This class was written to address permission issues when using Dependency-Check in a server environment (such as the
 * Jenkins plugin). In some circumstances, Velocity would attempt to create velocity.log in an un-writable
 * directory.</p>
 *
 * @author Steve Springett <steve.springett@owasp.org>
 */
public class VelocityLoggerRedirect implements LogChute {
    
    /**
     * The Logger.
     */
    private static final Logger LOGGER = Logger.getLogger(VelocityLoggerRedirect.class.getName());
    /**
     * This will be invoked once by the LogManager.
     *
     * @param rsvc the RuntimeServices
     */
    public void init(RuntimeServices rsvc) {
        // do nothing
    }

    /**
     * Given a Velocity log level and message, this method will call the appropriate Logger level and log the specified
     * values.
     *
     * @param level the logging level
     * @param message the message to be logged
     */
    public void log(int level, String message) {
        LOGGER.log(getLevel(level), message);
    }

    /**
     * Given a Velocity log level, message and Throwable, this method will call the appropriate Logger level and log the
     * specified values.
     *
     * @param level the logging level
     * @param message the message to be logged
     * @param t a throwable to log
     */
    public void log(int level, String message, Throwable t) {
        LOGGER.log(getLevel(level), message, t);
    }

    /**
     * Will always return true. The property file will decide what level to log.
     *
     * @param level the logging level
     * @return true
     */
    public boolean isLevelEnabled(int level) {
        return true;
    }

    /**
     * Maps Velocity log levels to {@link Logger} values.
     *
     * @param velocityLevel the logging level
     * @return the logging level
     */
    private Level getLevel(int velocityLevel) {
        switch (velocityLevel) {
            case TRACE_ID:
                return Level.ALL;
            case DEBUG_ID:
                return Level.FINE;
            case INFO_ID:
                return Level.INFO;
            case WARN_ID:
                return Level.WARNING;
            case ERROR_ID:
                return Level.SEVERE;
            default:
                return Level.INFO;
        }
    }
}
