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

import java.lang.reflect.InvocationTargetException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple factory to instantiate the Write Lock Shutdown Hook.
 *
 * @author Jeremy Long
 */
public final class WriteLockShutdownHookFactory {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(WriteLockShutdownHookFactory.class);

    /**
     * Empty constructor for utility class.
     */
    private WriteLockShutdownHookFactory() {
        //empty
    }

    /**
     * Creates a new Write Lock Shutdown Hook.
     *
     * @param settings the configured settings
     * @return the Write Lock Shutdown Hook
     */
    public static WriteLockShutdownHook getHook(Settings settings) {
        try {
            //Note - the write lock shutdown hook name is a setting because the shutdown hook is different in gradle
            final String className = settings.getString(Settings.KEYS.WRITELOCK_SHUTDOWN_HOOK,
                    "org.owasp.dependencycheck.utils.WriteLockCleanupHook");
            final Class<?> type = Class.forName(className);
            return (WriteLockShutdownHook) type.getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException
                | NoSuchMethodException | SecurityException | IllegalArgumentException | InvocationTargetException ex) {
            LOGGER.debug("Failed to instantiate specified shutdown hook, using default shutdown hook instead", ex);
            return new WriteLockCleanupHook();
        }
    }
}
