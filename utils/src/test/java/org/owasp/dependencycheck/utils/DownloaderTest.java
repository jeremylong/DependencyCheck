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
package org.owasp.dependencycheck.utils;

import java.io.File;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 *
 * @author Jeremy Long
 */
public class DownloaderTest extends BaseTest {

    @Test
    public void testGetLastModified_file() throws Exception {
        Downloader instance = new Downloader(getSettings());
        long timestamp = instance.getLastModified(new File("target/test-classes/dependencycheck.properties").toURI().toURL());
        assertTrue("timestamp equal to zero?", timestamp > 0);
    }
}
