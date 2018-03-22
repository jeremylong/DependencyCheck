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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple factory to instantiate the H2DB Shutdown Hook.
 *
 * @author Jeremy Long
 */
public final class H2DBShutdownHookFactory {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(H2DBShutdownHookFactory.class);

    /**
     * Empty constructor for utility class.
     */
    private H2DBShutdownHookFactory() {
        //empty
    }

    /**
     * Creates a new H2DB Shutdown Hook.
     *
     * @param settings the configured settings
     * @return the H2DB Shutdown Hook
     */
    public static H2DBShutdownHook getHook(Settings settings) {
        try {
            final String className = settings.getString(Settings.KEYS.H2DB_SHUTDOWN_HOOK, "org.owasp.dependencycheck.utils.H2DBCleanupHook");
            final Class<?> type = Class.forName(className);
            return (H2DBShutdownHook) type.newInstance();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException ex) {
            LOGGER.debug("Failed to instantiate {}, using default shutdown hook instead", ex);
            return new H2DBCleanupHook();
        }
    }
}
