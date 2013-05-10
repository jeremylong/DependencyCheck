/*
 * This file is part of Dependency-Check.
 *
 * Dependency-Check is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * Dependency-Check is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Dependency-Check. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.reporting;

import org.owasp.dependencycheck.data.cpe.BaseIndexTestCase;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class ReportGeneratorTest {

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
     * Test of generateReport method, of class ReportGenerator.
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testGenerateReport() throws Exception {
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
