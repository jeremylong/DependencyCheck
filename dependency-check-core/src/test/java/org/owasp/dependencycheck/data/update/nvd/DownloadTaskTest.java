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
 * Copyright (c) 2014 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.nvd;

import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.utils.Settings;

/**
 *
 * @author Jeremy Long
 */
public class DownloadTaskTest extends BaseTest {

    /**
     * Test of call method, of class DownloadTask.
     */
    @Test
    public void testCall() throws Exception {
        NvdCveInfo cve = new NvdCveInfo();
        cve.setId("modified");
        cve.setNeedsUpdate(true);
        cve.setUrl(getSettings().getString(Settings.KEYS.CVE_MODIFIED_20_URL));
        cve.setOldSchemaVersionUrl(getSettings().getString(Settings.KEYS.CVE_MODIFIED_12_URL));
        ExecutorService processExecutor = null;
        CveDB cveDB = null;
        DownloadTask instance = new DownloadTask(cve, processExecutor, cveDB, getSettings());
        Future<ProcessTask> result = instance.call();
        assertNull(result);
    }

    /**
     * Test of isXml(file).
     */
    @Test
    public void testIsXML() {
        File f = getResourceAsFile(this, "nvdcve-modified.xml");
        assertTrue(DownloadTask.isXml(f));
        f = getResourceAsFile(this, "file.tar.gz");
        assertFalse(DownloadTask.isXml(f));
    }
}
