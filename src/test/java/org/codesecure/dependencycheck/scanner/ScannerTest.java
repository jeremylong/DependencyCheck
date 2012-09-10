/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.scanner;

import org.codesecure.dependencycheck.data.cpe.CPEQuery;
import java.io.IOException;
import org.codesecure.dependencycheck.data.BaseIndexTestCase;
import java.io.File;
import java.util.List;
import java.util.Map;
import org.codesecure.dependencycheck.reporting.ReportGenerator;
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
public class ScannerTest extends BaseIndexTestCase{
    
    public ScannerTest(String testName) {
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
     * Test of scan method, of class Scanner.
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    //TODO remove the throws exception, this needs to be much more grainular.
    public void testScan() throws Exception {
        System.out.println("scan");
        String path = "./src/test/resources";
        Scanner instance = new Scanner();
        instance.scan(path);
        assertTrue(instance.getDependencies().size()>0);
        CPEQuery query = new CPEQuery();
        query.open();
        List<Dependency> dependencies = instance.getDependencies();
        for (Dependency d : dependencies) {
            query.determineCPE(d);
        }
        query.close();
        ReportGenerator rg = new ReportGenerator();
        rg.generateReports("./target/", "DependencyCheck", instance.getDependencies());

    }

}
