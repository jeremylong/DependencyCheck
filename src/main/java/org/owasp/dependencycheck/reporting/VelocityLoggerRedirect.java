/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Check. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.reporting;

import org.apache.velocity.app.Velocity;
import org.apache.velocity.runtime.RuntimeServices;
import org.apache.velocity.runtime.log.LogChute;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * DependencyCheck uses {@link java.util.logging.Logger} as a logging framework,
 * and Apache Velocity uses a custom logging implementation that outputs to a
 * file named velocity.log by default. This class is an implementation of a
 * custom Velocity logger that redirects all velocity logging to the Java Logger
 * class.
 * <p/>
 * This class was written to address permission issues when using DependencyCheck
 * in a server environment (such as the Jenkins plugin). In some circumstances,
 * Velocity would attempt to create velocity.log in an un-writable directory.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
public class VelocityLoggerRedirect implements LogChute {

    /**
     * This will be invoked once by the LogManager
     */
    public void init(RuntimeServices rsvc) {
        // do nothing
    }

    /**
     * Given a Velocity log level and message, this method will
     * call the appropriate Logger level and log the specified values.
     */
    public void log(int level, String message) {
        Logger.getLogger(Velocity.class.getName()).log(getLevel(level), message);
    }

    /**
     * Given a Velocity log level, message and Throwable, this method will
     * call the appropriate Logger level and log the specified values.
     */
    public void log(int level, String message, Throwable t) {
        Logger.getLogger(Velocity.class.getName()).log(getLevel(level), message, t);
    }

    /**
     * Will always return true. The property file will decide what level to log.
     */
    public boolean isLevelEnabled(int level) {
        return true;
    }

    /**
     * Maps Velocity log levels to {@link Logger} values.
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
