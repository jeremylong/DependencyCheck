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

import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.FileLockInterruptionException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.OverlappingFileLockException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Implements a spin lock on a given directory. If the lock cannot be obtained,
 * the process will "spin" waiting for an opportunity to obtain the lock
 * requested.
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DirectorySpinLock implements Closeable /*, AutoCloseable*/ {

    /**
     * The name of the lock file.
     */
    public static final String LOCK_NAME = "data.lock";
    /**
     * The maximum wait period used when attempting to obtain a lock.
     */
    public static final int MAX_SPIN = 100;
    /**
     * The file channel used to perform the lock.
     */
    private FileChannel channel = null;
    /**
     * The file used to perform the lock.
     */
    private File lockFile = null;
    /**
     * The lock object.
     */
    private FileLock lock = null;
    /**
     * The maximum number of seconds that the spin lock will wait while trying
     * to obtain a lock.
     */
    private long maxWait = MAX_SPIN;

    /**
     * Get the maximum wait time, in seconds, that the spin lock will wait while
     * trying to obtain a lock.
     *
     * @return the number of seconds the spin lock will wait
     */
    public long getMaxWait() {
        return maxWait / 2; //sleep is for 500, so / 2
    }

    /**
     * Set the maximum wait time, in seconds, that the spin lock will wait while
     * trying to obtain a lock.
     *
     * @param maxWait the number of seconds the spin lock will wait
     */
    public void setMaxWait(long maxWait) {
        this.maxWait = maxWait * 2; //sleep is for 500, so * 2
    }

    /**
     * Constructs a new spin lock on the given directory.
     *
     * @param directory the directory to monitor/lock
     * @throws InvalidDirectoryException thrown if there is an issue with the
     * directory provided
     * @throws DirectoryLockException thrown there is an issue obtaining a
     * handle to the lock file
     */
    public DirectorySpinLock(File directory) throws InvalidDirectoryException, DirectoryLockException {
        checkDirectory(directory);
        lockFile = new File(directory, LOCK_NAME);
        RandomAccessFile file = null;
        try {
            file = new RandomAccessFile(lockFile, "rw");
        } catch (FileNotFoundException ex) {
            throw new DirectoryLockException("Lock file not found", ex);
        }
        channel = file.getChannel();
    }

    /**
     * Attempts to obtain an exclusive lock; an exception is thrown if the lock
     * could not be obtained. This method may block for a few seconds if a lock
     * cannot be obtained.
     *
     * @throws DirectoryLockException thrown if there is an exception obtaining
     * the lock
     */
    public void obtainSharedLock() throws DirectoryLockException {
        obtainLock(true);
    }

    /**
     * Attempts to obtain an exclusive lock; an exception is thrown if the lock
     * could not be obtained. This method may block for a few seconds if a lock
     * cannot be obtained.
     *
     * @throws DirectoryLockException thrown if there is an exception obtaining
     * the lock
     */
    public void obtainExclusiveLock() throws DirectoryLockException {
        obtainLock(false);
    }

    /**
     * Attempts to obtain a lock; an exception is thrown if the lock could not
     * be obtained. This method may block for a few seconds if a lock cannot be
     * obtained.
     *
     * @param shared true if the lock is shared, otherwise false
     * @param maxWait the maximum time to wait, in seconds, while trying to
     * obtain the lock
     * @throws DirectoryLockException thrown if there is an exception obtaining
     * the lock
     */
    protected void obtainLock(boolean shared, long maxWait) throws DirectoryLockException {
        setMaxWait(maxWait);
        obtainLock(shared);
    }

    /**
     * Attempts to obtain a lock; an exception is thrown if the lock could not
     * be obtained. This method may block for a few seconds if a lock cannot be
     * obtained.
     *
     * @param shared true if the lock is shared, otherwise false
     * @throws DirectoryLockException thrown if there is an exception obtaining
     * the lock
     */
    protected void obtainLock(boolean shared) throws DirectoryLockException {
        if (lock != null) {
            release();
        }
        if (channel == null) {
            throw new DirectoryLockException("Unable to create lock, no file channel exists");
        }
        int count = 0;
        Exception lastException = null;
        while (lock == null && count++ < maxWait) {
            try {
                lock = channel.lock(0, Long.MAX_VALUE, shared);
            } catch (AsynchronousCloseException ex) {
                lastException = ex;
            } catch (ClosedChannelException ex) {
                lastException = ex;
            } catch (FileLockInterruptionException ex) {
                lastException = ex;
            } catch (OverlappingFileLockException ex) {
                lastException = ex;
            } catch (NonWritableChannelException ex) {
                lastException = ex;
            } catch (IOException ex) {
                lastException = ex;
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
        }
        if (lock == null) {
            if (lastException == null) {
                throw new DirectoryLockException("Unable to obtain lock");
            } else {
                throw new DirectoryLockException("Unable to obtain lock", lastException);
            }
        }
    }

    /**
     * Performs a few simple rudimentary checks on the specified directory.
     * Specifically, does the file exist and is it a directory.
     *
     * @param directory the File object to inspect
     * @throws InvalidDirectoryException thrown if the directory is null or is
     * not a directory
     */
    private void checkDirectory(File directory) throws InvalidDirectoryException {
        if (directory == null) {
            throw new InvalidDirectoryException("Unable to obtain lock on a null File");
        }
        if (!directory.isDirectory()) {
            final String msg = String.format("File, '%s', does not exist or is not a directory", directory.getAbsolutePath());
            throw new InvalidDirectoryException(msg);
        }
    }

    /**
     * Releases any locks and closes the underlying channel.
     *
     * @throws IOException if an IO Exception occurs
     */
    @Override
    public void close() throws IOException {
        release();
// TODO uncomment this once support for 1.6 is dropped.
//        if (lock != null) {
//            try {
//                lock.close();
//            } catch (IOException ex) {
//                Logger.getLogger(DirectorySpinLock.class.getName()).log(Level.FINEST, "Unable to close file lock due to IO Exception", ex);
//            }
//        }
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException ex) {
                Logger.getLogger(DirectorySpinLock.class.getName()).log(Level.FINEST, "Unable to close the channel for the file lock", ex);
            }
        }
        if (lockFile != null) {
            if (lockFile.exists()) {
                /* yes, this delete could fail which is totally fine. The other
                 * thread holding the lock while delete it.
                 */
                lockFile.delete();
            }
        }
    }

    /**
     * Releases the lock. Any exceptions that are thrown by the underlying lock
     * during the release are ignored.
     */
    public void release() {
        if (lock != null) {
            try {
                lock.release();
            } catch (ClosedChannelException ex) {
                Logger.getLogger(DirectorySpinLock.class.getName()).log(Level.FINEST, "Unable to release file lock", ex);
            } catch (IOException ex) {
                Logger.getLogger(DirectorySpinLock.class.getName()).log(Level.FINEST, "Unable to release file lock due to IO Exception", ex);
            }
        }
    }
}
