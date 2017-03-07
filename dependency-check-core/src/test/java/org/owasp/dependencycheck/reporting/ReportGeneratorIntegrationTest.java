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
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.reporting;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import org.xml.sax.SAXException;

/**
 *
 * @author Jeremy Long
 */
public class ReportGeneratorIntegrationTest extends BaseDBTestCase {

    /**
     * Test of generateReport method, of class ReportGenerator.
     *
     * @throws Exception is thrown when an exception occurs.
     */
    @Test
    public void testGenerateReport() throws Exception {
//        String templateName = "HtmlReport";
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
        //assertTrue("need to add a real check here", false);
    }

    /**
     * Generates an XML report containing known vulnerabilities and realistic data and validates the generated XML document
     * against the XSD.
     *
     * @throws Exception
     */
    @Test
    public void testGenerateXMLReport() {
        try {
            String templateName = "XmlReport";
            
            File f = new File("target/test-reports");
            if (!f.exists()) {
                f.mkdir();
            }
            String writeTo = "target/test-reports/Report.xml";
            File suppressionFile = BaseTest.getResourceAsFile(this, "incorrectSuppressions.xml");
            
            Settings.setString(Settings.KEYS.SUPPRESSION_FILE, suppressionFile.getAbsolutePath());
            
            //File struts = new File(this.getClass().getClassLoader().getResource("struts2-core-2.1.2.jar").getPath());
            File struts = BaseTest.getResourceAsFile(this, "struts2-core-2.1.2.jar");
            //File axis = new File(this.getClass().getClassLoader().getResource("axis2-adb-1.4.1.jar").getPath());
            File axis = BaseTest.getResourceAsFile(this, "axis2-adb-1.4.1.jar");
            //File jetty = new File(this.getClass().getClassLoader().getResource("org.mortbay.jetty.jar").getPath());
            File jetty = BaseTest.getResourceAsFile(this, "org.mortbay.jetty.jar");
            
            boolean autoUpdate = Settings.getBoolean(Settings.KEYS.AUTO_UPDATE);
            Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            Engine engine = new Engine();
            Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, autoUpdate);
            
            engine.scan(struts);
            engine.scan(axis);
            engine.scan(jetty);
            engine.analyzeDependencies();
            
            CveDB cveDB = CveDB.getInstance();
            DatabaseProperties dbProp = cveDB.getDatabaseProperties();
            
            ReportGenerator generator = new ReportGenerator("Test Report", engine.getDependencies(), engine.getAnalyzers(), dbProp);
            generator.generateReport(templateName, writeTo);
            
            engine.cleanup();
            
            InputStream xsdStream = ReportGenerator.class.getClassLoader().getResourceAsStream("schema/dependency-check.1.4.xsd");
            StreamSource xsdSource = new StreamSource(xsdStream);
            StreamSource xmlSource = new StreamSource(new File(writeTo));
            SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = sf.newSchema(xsdSource);
            Validator validator = schema.newValidator();
            validator.validate(xmlSource);
        } catch (InvalidSettingException ex) {
            fail(ex.getMessage());
        } catch (DatabaseException | ExceptionCollection | ReportException | SAXException | IOException ex) {
            fail(ex.getMessage());
        }
    }
}
