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
import java.net.URL;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class DirectorySpinLockTest {

    public DirectorySpinLockTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of obtainSharedLock method, of class DirectorySpinLock.
     * Specifically, this test uses the SpinLockTask to obtain an exclusive lock
     * that is held for 5 seconds. We then try to obtain a shared lock while
     * that task is running. It should take longer then 5 seconds to obtain the
     * shared lock.
     */
    @Test
    public void testObtainSharedLock_withContention() throws Exception {
        URL location = this.getClass().getProtectionDomain().getCodeSource().getLocation();
        File directory = new File(location.getFile());
        DirectorySpinLock instance = new DirectorySpinLock(directory);
        SpinLockTask task = new SpinLockTask(directory, 5000, false, 2);
        long start = System.currentTimeMillis();
        task.run();
        instance.obtainSharedLock();
        long end = System.currentTimeMillis();
        instance.close();
        if (task.getException() != null) {
            throw task.getException();
        }
        long timeElapsed = end - start;
        assertTrue("no lock contention occurred?", timeElapsed >= 5000);
        //no exceptions means everything worked.
    }

    /**
     * Test of obtainSharedLock method, of class DirectorySpinLock. This method
     * obtains two shared locks by using the SpinLockTask to obtain a lock in
     * another thread.
     */
    @Test
    public void testObtainSharedLock() throws Exception {
        URL location = this.getClass().getProtectionDomain().getCodeSource().getLocation();
        File directory = new File(location.getFile());
        DirectorySpinLock instance = new DirectorySpinLock(directory);
        SpinLockTask task = new SpinLockTask(directory, 1000, true, 2);
        task.run();
        instance.obtainSharedLock();
        instance.close();
        if (task.getException() != null) {
            throw task.getException();
        }
        //no exceptions means everything worked.
    }

    /**
     * Test of obtainExclusiveLock method, of class DirectorySpinLock.
     */
    @Test
    public void testObtainExclusiveLock() throws Exception {
        URL location = this.getClass().getProtectionDomain().getCodeSource().getLocation();
        File directory = new File(location.getFile());
        DirectorySpinLock instance = new DirectorySpinLock(directory);
        SpinLockTask task = new SpinLockTask(directory, 1000, true, 1);
        instance.obtainExclusiveLock();
        task.run();
        instance.close();
        assertNotNull("No exception thrown due to exclusive lock failure?", task.getException());
        assertEquals("Incorrect exception when obtaining exclusive lock", "Unable to obtain lock", task.getException().getMessage());
    }
}
