/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.reporting;

import org.codesecure.dependencycheck.data.cpe.BaseIndexTestCase;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class ReportGeneratorTest extends BaseIndexTestCase {

    public ReportGeneratorTest(String testName) {
        super(testName);
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    @Override
    public void setUp() {
    }

    @After
    @Override
    public void tearDown() {
    }

    /**
     * Test of generateReport method, of class ReportGenerator.
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testGenerateReport() throws Exception {
        System.out.println("generateReport");
        String templateName = "HtmlReport";
//        File f = new File("target/test-reports");
//        if (!f.exists()) {
//            f.mkdir();
//        }
//        String writeTo = "target/test-reports/Report.html";
//        Map<String, Object> properties = new HashMap<String, Object>();
//        Dependency d = new Dependency();
//        d.setFileName("FileName.jar");
//        d.setActualFilePath("lib/FileName.jar");
//        d.addCPEentry("cpe://a:/some:cpe:1.0");
//
//        List<Dependency> dependencies = new ArrayList<Dependency>();
//        d.getProductEvidence().addEvidence("jar","filename","<test>test", Confidence.HIGH);
//        d.getProductEvidence().addEvidence("manifest","vendor","<test>test", Confidence.HIGH);
//
//        for (Evidence e : d.getProductEvidence().iterator(Confidence.HIGH)) {
//            String t = e.getValue();
//        }
//        dependencies.add(d);
//
//        Dependency d2 = new Dependency();
//        d2.setFileName("Another.jar");
//        d2.setActualFilePath("lib/Another.jar");
//        d2.addCPEentry("cpe://a:/another:cpe:1.0");
//        d2.addCPEentry("cpe://a:/another:cpe:1.1");
//        d2.addCPEentry("cpe://a:/another:cpe:1.2");
//        d2.getProductEvidence().addEvidence("jar","filename","another.jar", Confidence.HIGH);
//        d2.getProductEvidence().addEvidence("manifest","vendor","Company A", Confidence.MEDIUM);
//
//        for (Evidence e : d2.getProductEvidence().iterator(Confidence.HIGH)) {
//            String t = e.getValue();
//        }
//
//        dependencies.add(d2);
//
//        Dependency d3 = new Dependency();
//        d3.setFileName("Third.jar");
//        d3.setActualFilePath("lib/Third.jar");
//        d3.getProductEvidence().addEvidence("jar","filename","third.jar", Confidence.HIGH);
//
//        for (Evidence e : d3.getProductEvidence().iterator(Confidence.HIGH)) {
//            String t = e.getValue();
//        }
//
//        dependencies.add(d3);
//
//        properties.put("dependencies",dependencies);
//
//        ReportGenerator instance = new ReportGenerator();
//        instance.generateReport(templateName, writeTo, properties);
        //TODO add an assertion here...
        //assertTrue("need to add a real check here", false);
    }
}
