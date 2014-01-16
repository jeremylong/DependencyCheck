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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.concurrency;

import java.io.File;
import java.io.IOException;

/**
 * A simple task that obtains a lock on a directory. This is used in testing of the shared and exclusive locks.
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
