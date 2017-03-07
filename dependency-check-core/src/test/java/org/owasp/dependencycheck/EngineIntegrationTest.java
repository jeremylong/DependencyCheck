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
package org.owasp.dependencycheck;

import java.io.IOException;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.reporting.ReportGenerator;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long
 */
public class EngineIntegrationTest extends BaseDBTestCase {

    /**
     * Test running the entire engine.
     *
     * @throws java.io.IOException
     * @throws org.owasp.dependencycheck.utils.InvalidSettingException
     * @throws org.owasp.dependencycheck.data.nvdcve.DatabaseException
     * @throws org.owasp.dependencycheck.exception.ReportException
     * @throws org.owasp.dependencycheck.exception.ExceptionCollection
     */
    @Test
    public void testEngine() throws IOException, InvalidSettingException, DatabaseException, ReportException, ExceptionCollection {
        String testClasses = "target/test-classes";
        boolean autoUpdate = Settings.getBoolean(Settings.KEYS.AUTO_UPDATE);
        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        Engine instance = new Engine();
        Settings.setBoolean(Settings.KEYS.AUTO_UPDATE, autoUpdate);
        instance.scan(testClasses);
        assertTrue(instance.getDependencies().size() > 0);
        try {
            instance.analyzeDependencies();
        } catch (ExceptionCollection ex) {
            if (ex.getExceptions().size() == 1
                    && (ex.getExceptions().get(0).getMessage().contains("bundle-audit")
                    || ex.getExceptions().get(0).getMessage().contains("AssemblyAnalyzer"))) {
                //this is fine to ignore
            } else if (ex.getExceptions().size() == 2
                    && ((ex.getExceptions().get(0).getMessage().contains("bundle-audit")
                    && ex.getExceptions().get(1).getMessage().contains("AssemblyAnalyzer"))
                    || (ex.getExceptions().get(1).getMessage().contains("bundle-audit")
                    && ex.getExceptions().get(0).getMessage().contains("AssemblyAnalyzer")))) {
                //this is fine to ignore
            } else {
                throw ex;
            }
        }
        CveDB cveDB = CveDB.getInstance();
        DatabaseProperties dbProp = cveDB.getDatabaseProperties();
        ReportGenerator rg = new ReportGenerator("DependencyCheck", instance.getDependencies(), instance.getAnalyzers(), dbProp);
        rg.generateReports("./target/", "ALL");
        instance.cleanup();
    }
}
