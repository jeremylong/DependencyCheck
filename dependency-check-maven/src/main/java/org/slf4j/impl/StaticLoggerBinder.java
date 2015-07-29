/*
 * This file is part of dependency-check-ant.
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
 * Copyright (c) 2015 The OWASP Foundation. All Rights Reserved.
 */
package org.slf4j.impl;

import org.apache.maven.plugin.logging.Log;
import org.owasp.dependencycheck.maven.slf4j.MavenLoggerFactory;
import org.slf4j.ILoggerFactory;
import org.slf4j.spi.LoggerFactoryBinder;

/**
 * The binding of {@link org.slf4j.LoggerFactory} class with an actual instance of {@link ILoggerFactory} is performed using
 * information returned by this class.
 *
 * @author colezlaw
 */
public class StaticLoggerBinder implements LoggerFactoryBinder {

    /**
     * The unique instance of this class
     */
    private static final StaticLoggerBinder SINGLETON = new StaticLoggerBinder();

    /**
     * Return the singleton of this class.
     *
     * @return the StaticLoggerBinder singleton
     */
    public static final StaticLoggerBinder getSingleton() {
        return SINGLETON;
    }

    /**
     * Maven mojos have their own logger, so we'll use one of those
     */
    private Log log = null;

    /**
     * Set the Task which will this is to log through.
     *
     * @param log the task through which to log
     */
    public void setLog(Log log) {
        this.log = log;
        loggerFactory = new MavenLoggerFactory(log);
    }

    /**
     * Declare the version of the SLF4J API this implementation is compiled against. The value of this filed is usually modified
     * with each release.
     */
    // to avoid constant folding by the compiler, this field must *not* be final
    public static String REQUESTED_API_VERSION = "1.7.12"; // final

    /**
     * The logger factory class string.
     */
    private static final String LOGGER_FACTORY_CLASS = MavenLoggerFactory.class.getName();

    /**
     * The ILoggerFactory instance returned by the {@link #getLoggerFactory} method should always be the same object
     */
    private ILoggerFactory loggerFactory;

    /**
     * Constructs the static logger factory.
     */
    private StaticLoggerBinder() {
        loggerFactory = new MavenLoggerFactory(log);
    }

    /**
     * Returns the logger factory.
     *
     * @return the logger factory
     */
    @Override
    public ILoggerFactory getLoggerFactory() {
        return loggerFactory;
    }

    /**
     * Returns the logger factory class string.
     *
     * @return the logger factory class string
     */
    @Override
    public String getLoggerFactoryClassStr() {
        return LOGGER_FACTORY_CLASS;
    }
}
