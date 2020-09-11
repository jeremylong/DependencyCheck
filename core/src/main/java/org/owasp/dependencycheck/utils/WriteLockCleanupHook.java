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
 * A cleanup hook that will register with the JVM to remove the WriteLock file
 * during an unexpected shutdown.
 *
 * @author Jeremy Long
 */
public class WriteLockCleanupHook extends WriteLockShutdownHook {

    /**
     * A reference to the lock file.
     */
    private WriteLock lock;

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(WriteLockCleanupHook.class);

    /**
     * Add the shutdown hook.
     *
     * @param lock the lock object
     */
    @Override
    public void add(WriteLock lock) {
        this.lock = lock;
        Runtime.getRuntime().addShutdownHook(this);
    }

    /**
     * Removes the shutdown hook.
     */
    @Override
    public void remove() {
        try {
            Runtime.getRuntime().removeShutdownHook(this);
        } catch (IllegalStateException ex) {
            LOGGER.trace("ignore as we are likely shutting down", ex);
        }
    }

    /**
     * Releases the custom h2 lock file used by dependency-check.
     */
    @Override
    public void run() {
        if (lock != null) {
            lock.close();
            lock = null;
        }
    }
}
