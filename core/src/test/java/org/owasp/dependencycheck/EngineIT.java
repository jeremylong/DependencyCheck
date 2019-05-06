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

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.ReportException;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;
import static org.junit.Assert.assertTrue;

/**
 *
 * @author Jeremy Long
 */
public class EngineIT extends BaseDBTestCase {

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
        getSettings().setBoolean(Settings.KEYS.AUTO_UPDATE, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NODE_PACKAGE_ENABLED, false);
        getSettings().setBoolean(Settings.KEYS.ANALYZER_NODE_AUDIT_ENABLED, false);
        try (Engine instance = new Engine(getSettings())) {
            instance.scan(testClasses);
            assertTrue(instance.getDependencies().length > 0);
            try {
                instance.analyzeDependencies();
            } catch (ExceptionCollection ex) {
                Set<String> allowedMessages = new HashSet<>();
                allowedMessages.add("bundle-audit");
                allowedMessages.add("AssemblyAnalyzer");
                allowedMessages.add("ailed to read results from the NPM Audit API");
                for (Throwable t : ex.getExceptions()) {
                    boolean isOk = false;
                    if (t.getMessage() != null) {
                        for (String msg : allowedMessages) {
                            if (t.getMessage().contains(msg)) {
                                isOk = true;
                                break;
                            }
                        }
                    }
                    if (!isOk) {
                        throw ex;
                    }
                }
            }
            instance.writeReports("dependency-check sample", new File("./target/"), "ALL");
        }
    }
}
