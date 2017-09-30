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
 * Copyright (c) 2013 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update;

import org.junit.Test;
import org.owasp.dependencycheck.BaseDBTestCase;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.data.update.nvd.UpdateableNvdCve;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import org.owasp.dependencycheck.Engine;

/**
 *
 * @author Jeremy Long
 */
public class NvdCveUpdaterIT extends BaseDBTestCase {

    /**
     * Test of updatesNeeded method.
     */
    @Test
    public void testUpdatesNeeded() throws Exception {
        NvdCveUpdater instance = new NvdCveUpdater();
        instance.setSettings(getSettings());
        instance.initializeExecutorServices();
        UpdateableNvdCve result = instance.getUpdatesNeeded();
        assertNotNull(result);
    }
}
