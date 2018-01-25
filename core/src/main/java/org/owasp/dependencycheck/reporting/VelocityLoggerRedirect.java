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

import javax.annotation.concurrent.ThreadSafe;
import org.apache.velocity.runtime.RuntimeServices;
import org.apache.velocity.runtime.log.LogChute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * DependencyCheck uses {@link org.slf4j.Logger} as a logging framework, and
 * Apache Velocity uses a custom logging implementation that outputs to a file
 * named velocity.log by default. This class is an implementation of a custom
 * Velocity logger that redirects all velocity logging to the Java Logger class.
 * </p><p>
 * This class was written to address permission issues when using
 * Dependency-Check in a server environment (such as the Jenkins plugin). In
 * some circumstances, Velocity would attempt to create velocity.log in an
 * un-writable directory.</p>
 *
 * @author Steve Springett
 */
@ThreadSafe
public class VelocityLoggerRedirect implements LogChute {

    /**
     * The Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(VelocityLoggerRedirect.class);

    /**
     * This will be invoked once by the LogManager.
     *
     * @param rsvc the RuntimeServices
     */
    @Override
    public void init(RuntimeServices rsvc) {
        // do nothing
    }

    /**
     * Given a Velocity log level and message, this method will call the
     * appropriate Logger level and log the specified values.
     *
     * @param level the logging level
     * @param message the message to be logged
     */
    @Override
    public void log(int level, String message) {
        switch (level) {
            case TRACE_ID:
                LOGGER.trace(message);
                break;
            case DEBUG_ID:
                LOGGER.debug(message);
                break;
            case INFO_ID:
                LOGGER.info(message);
                break;
            case WARN_ID:
                LOGGER.warn(message);
                break;
            case ERROR_ID:
                LOGGER.error(message);
                break;
            default:
                LOGGER.info(message);
                break;
        }
    }

    /**
     * Given a Velocity log level, message and Throwable, this method will call
     * the appropriate Logger level and log the specified values.
     *
     * @param level the logging level
     * @param message the message to be logged
     * @param t a throwable to log
     */
    @Override
    public void log(int level, String message, Throwable t) {
        switch (level) {
            case TRACE_ID:
                LOGGER.trace(message, t);
                break;
            case DEBUG_ID:
                LOGGER.debug(message, t);
                break;
            case INFO_ID:
                LOGGER.info(message, t);
                break;
            case WARN_ID:
                LOGGER.warn(message, t);
                break;
            case ERROR_ID:
                LOGGER.error(message, t);
                break;
            default:
                LOGGER.info(message, t);
                break;
        }
    }

    /**
     * Will always return true. The property file will decide what level to log.
     *
     * @param level the logging level
     * @return true
     */
    @Override
    public boolean isLevelEnabled(int level) {
        return true;
    }
}
