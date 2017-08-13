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

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.util.Date;
import org.owasp.dependencycheck.data.nvdcve.ConnectionFactory;
import org.owasp.dependencycheck.exception.H2DBLockException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Jeremy Long
 */
public class H2DBLock {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(H2DBLock.class);
    /**
     * The file lock.
     */
    private FileLock lock = null;
    /**
     * Reference to the file that we are locking.
     */
    private RandomAccessFile file = null;
    /**
     * The lock file.
     */
    private File lockFile = null;

    /**
     * Determine if the lock is currently held.
     *
     * @return true if the lock is currently held
     */
    public boolean isLocked() {
        return lock != null && lock.isValid();
    }

    /**
     * Obtains a lock on the H2 database.
     *
     * @throws H2DBLockException thrown if a lock could not be obtained
     */
    public void lock() throws H2DBLockException {
        if (ConnectionFactory.isH2Connection()) {
            try {
                final File dir = Settings.getDataDirectory();
                lockFile = new File(dir, "dc.update.lock");
                if (lockFile.isFile() && getFileAge(lockFile) > 5 && !lockFile.delete()) {
                    LOGGER.warn("An old db update lock file was found but the system was unable to delete "
                            + "the file. Consider manually deleting {}", lockFile.getAbsolutePath());
                }
                int ctr = 0;
                do {
                    try {
                        if (!lockFile.exists() && lockFile.createNewFile()) {
                            file = new RandomAccessFile(lockFile, "rw");
                            lock = file.getChannel().lock();
                        }
                    } catch (IOException ex) {
                        LOGGER.trace("Expected error as another thread has likely locked the file", ex);
                    } finally {
                        if (lock == null && file != null) {
                            try {
                                file.close();
                            } catch (IOException ex) {
                                LOGGER.trace("Unable to close the ulFile", ex);
                            }
                        }
                    }
                    if (lock == null || !lock.isValid()) {
                        try {
                            LOGGER.debug("Sleeping thread {} for 5 seconds because we could not obtain the update lock.",
                                    Thread.currentThread().getName());
                            Thread.sleep(5000);
                        } catch (InterruptedException ex) {
                            LOGGER.trace("ignorable error, sleep was interrupted.", ex);
                            Thread.currentThread().interrupt();
                        }
                    }
                } while (++ctr < 60 && (lock == null || !lock.isValid()));
                if (lock == null || !lock.isValid()) {
                    throw new H2DBLockException("Unable to obtain the update lock, skipping the database update. Skippinig the database update.");
                }
            } catch (IOException ex) {
                throw new H2DBLockException(ex.getMessage(), ex);
            }
        }
    }

    /**
     * Releases the lock on the H2 database.
     */
    public void release() {
        if (lock != null) {
            try {
                lock.release();
                lock = null;
            } catch (IOException ex) {
                LOGGER.trace("Ignorable exception", ex);
            }
        }
        if (file != null) {
            try {
                file.close();
                file = null;
            } catch (IOException ex) {
                LOGGER.trace("Ignorable exception", ex);
            }
        }
        if (lockFile != null && lockFile.isFile() && !lockFile.delete()) {
            LOGGER.error("Lock file '{}' was unable to be deleted. Please manually delete this file.", lockFile.toString());
            lockFile.deleteOnExit();
        }
        lockFile = null;
    }

    /**
     * Returns the age of the file in minutes.
     *
     * @param file the file to calculate the age
     * @return the age of the file
     */
    private long getFileAge(File file) {
        final Date d = new Date();
        final long modified = file.lastModified();
        return (d.getTime() - modified) / 1000 / 60;
    }
}
