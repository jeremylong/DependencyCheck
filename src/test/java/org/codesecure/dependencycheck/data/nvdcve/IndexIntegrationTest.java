/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.nvdcve;

import java.io.File;
import java.util.Map;
import org.apache.lucene.store.Directory;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.*;

/**
 *
 * @author Jeremy
 */
public class IndexIntegrationTest extends BaseIndexTestCase {
    
    public IndexIntegrationTest(String testName) {
        super(testName);
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
     * Test of retrieveCurrentTimestampFromWeb method, of class Index.
     */
    @Test
    public void testRetrieveCurrentTimestampFromWeb() throws Exception {
        System.out.println("retrieveCurrentTimestampFromWeb");
        Index instance = new Index();
        Map<String, Index.NvdCveUrl> result = instance.retrieveCurrentTimestampsFromWeb();
        assertEquals(12, result.size());        
    }

    /**
     * Test of getDirectory method, of class Index.
     */
    @Test
    public void testGetDirectory() throws Exception {
        System.out.println("getDirectory");
        Index instance = new Index();
        String exp = File.separatorChar + "target" + File.separatorChar + "data" + File.separatorChar + "cve";
        Directory result = instance.getDirectory();
        assertTrue(result.toString().contains(exp));
    }

    /**
     * Test of update method, of class Index.
     */
    @Test
    public void testUpdate() throws Exception {
        System.out.println("update");
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
        instance.updateNeeded();
        //if an exception is thrown this test fails. However, because it depends on the
        //  order of the tests what this will return I am just testing for the exception.
    }

}
