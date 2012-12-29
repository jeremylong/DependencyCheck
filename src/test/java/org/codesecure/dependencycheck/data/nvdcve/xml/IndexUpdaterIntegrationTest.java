/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.data.nvdcve.xml;


import java.util.Map;
import org.codesecure.dependencycheck.data.nvdcve.BaseIndexTestCase;
import org.junit.*;

/**
 * 
 * @author Jeremy
 */
public class IndexUpdaterIntegrationTest extends BaseIndexTestCase {

    public IndexUpdaterIntegrationTest(String testName) {
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
        IndexUpdater instance = new IndexUpdater();
        Map<String, IndexUpdater.NvdCveUrl> result = instance.retrieveCurrentTimestampsFromWeb();
        assertEquals(12, result.size());
    }

    /**
     * Test of update method, of class Index.
     */
    @Test
    public void testUpdate() throws Exception {
        System.out.println("update");
        IndexUpdater instance = new IndexUpdater();
        instance.update();
    }

    /**
     * Test of updateNeeded method, of class Index.
     */
    @Test
    public void testUpdateNeeded() throws Exception {
        System.out.println("updateNeeded");
        IndexUpdater instance = new IndexUpdater();
        instance.updateNeeded();
        //if an exception is thrown this test fails. However, because it depends on the
        //  order of the tests what this will return I am just testing for the exception.
    }
}
