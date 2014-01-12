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
package org.owasp.dependencycheck.concurrency;

import java.io.File;
import java.io.IOException;

/**
 * A simple task that obtains a lock on a directory. This is used in testing of
 * the shared and exclusive locks.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class SpinLockTask implements Runnable {

    DirectorySpinLock lock = null;
    int holdLockFor;
    long maxWait;
    boolean shared;
    private Exception exception = null;

    /**
     * Get the value of exception
     *
     * @return the value of exception
     */
    public Exception getException() {
        return exception;
    }

    /**
     * Set the value of exception
     *
     * @param exception new value of exception
     */
    public void setException(Exception exception) {
        this.exception = exception;
    }

    public SpinLockTask(File directory, int holdLockFor, boolean shared, long maxWait) throws InvalidDirectoryException, DirectoryLockException {
        this.holdLockFor = holdLockFor;
        this.shared = shared;
        this.maxWait = maxWait;
        lock = new DirectorySpinLock(directory);
    }

    @Override
    public void run() {
        try {
            lock.obtainLock(shared, maxWait);
            Thread.sleep(holdLockFor);
        } catch (DirectoryLockException ex) {
            exception = ex;
        } catch (InterruptedException ex) {
            exception = ex;
        } finally {
            if (lock != null) {
                try {
                    lock.close();
                } catch (IOException ex) {
                    exception = ex;
                }
            }
        }
    }
}
