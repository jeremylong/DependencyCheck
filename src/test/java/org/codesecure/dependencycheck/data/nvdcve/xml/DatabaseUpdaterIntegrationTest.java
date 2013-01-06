/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.nvdcve.xml;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class DatabaseUpdaterIntegrationTest {

    public DatabaseUpdaterIntegrationTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of update method, of class DatabaseUpdater.
     * @throws Exception
     */
    @Test
    public void testUpdate() throws Exception {
        System.out.println("update");
        DatabaseUpdater instance = new DatabaseUpdater();
        instance.update();
    }
}
