/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.cpe;

import java.io.File;
import org.codesecure.dependencycheck.data.lucene.BaseIndexTestCase;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.store.Directory;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class IndexTest extends BaseIndexTestCase {

    public IndexTest(String testCase) {
        super(testCase);
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
     * Test of open method, of class Index.
     */
    @Test
    public void testOpen() {
        System.out.println("open");
        Index instance = new Index();
        try {
            instance.open();
        } catch (IOException ex) {
            fail(ex.getMessage());
        }
        instance.close();
    }

    /**
     * Test of getDirectory method, of class Index.
     */
    @Test
    public void testGetDirectory() throws Exception {
        System.out.println("getDirectory");
        Index index = new Index();
        Directory result = index.getDirectory();
        
        String exp = File.separatorChar + "target" + File.separatorChar + "store" + File.separatorChar + "cpe";
        // TODO review the generated test code and remove the default call to fail.
        assertTrue(result.toString().contains(exp));
    }

    /**
     * Test of update method, of class Index.
     */
    @Test
    public void testUpdateIndexFromWeb() throws Exception {
        System.out.println("updateIndexFromWeb");
        Index instance = new Index();
        instance.update();
    }

    /**
     * Test of updateNeeded method, of class Index.
     */
    @Test
    public void testUpdateNeeded() throws Exception {
        System.out.println("updateNeeded");
        Index instance = new Index();
        long expResult = 0L;
        long result = instance.updateNeeded();
        //if an exception is thrown this test fails. However, because it depends on the
        //  order of the tests what this will return I am just testing for the exception.
        //assertTrue(expResult < result);
    }
}
