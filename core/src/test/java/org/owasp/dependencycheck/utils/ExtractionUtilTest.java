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
 * Copyright (c) 2018 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.utils;

import java.io.File;
import java.io.FilenameFilter;
import org.apache.commons.io.filefilter.NameFileFilter;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.Engine;

/**
 *
 * @author Jeremy Long
 */
public class ExtractionUtilTest extends BaseTest {

    /**
     * Test of extractFiles method, of class ExtractionUtil.
     */
    @Test(expected = org.owasp.dependencycheck.utils.ExtractionException.class)
    public void testExtractFiles_File_File() throws Exception {
        File destination = getSettings().getTempDirectory();
        File archive = BaseTest.getResourceAsFile(this, "evil.zip");
        ExtractionUtil.extractFiles(archive, destination);
    }

    /**
     * Test of extractFiles method, of class ExtractionUtil.
     */
    @Test(expected = org.owasp.dependencycheck.utils.ExtractionException.class)
    public void testExtractFiles_3args() throws Exception {
        File destination = getSettings().getTempDirectory();
        File archive = BaseTest.getResourceAsFile(this, "evil.zip");
        Engine engine = null;
        ExtractionUtil.extractFiles(archive, destination, engine);
    }

    /**
     * Test of extractFilesUsingFilter method, of class ExtractionUtil.
     */
    @Test(expected = org.owasp.dependencycheck.utils.ExtractionException.class)
    public void testExtractFilesUsingFilter() throws Exception {
        File destination = getSettings().getTempDirectory();
        File archive = BaseTest.getResourceAsFile(this, "evil.zip");
        ExtractionUtil.extractFiles(archive, destination);
        FilenameFilter filter = new NameFileFilter("evil.txt");
        ExtractionUtil.extractFilesUsingFilter(archive, destination, filter);
    }
}
