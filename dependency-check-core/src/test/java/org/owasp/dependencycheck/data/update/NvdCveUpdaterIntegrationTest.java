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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.data.update.nvd.UpdateableNvdCve;

/**
 *
 * @author Jeremy Long
 */
public class NvdCveUpdaterIntegrationTest extends BaseTest {

    public NvdCveUpdater getUpdater() {
        NvdCveUpdater instance = new NvdCveUpdater();
        instance.initializeExecutorServices();
        return instance;
    }

    /**
     * Test of update method.
     */
    @Test
    public void testUpdate() {
        try {
            NvdCveUpdater instance = getUpdater();
            instance.update();
        } catch (UpdateException ex) {
            fail(ex.getMessage());
        }
    }

    /**
     * Test of updatesNeeded method.
     */
    @Test
    public void testUpdatesNeeded() throws Exception {
        NvdCveUpdater instance = getUpdater();
        UpdateableNvdCve result = instance.getUpdatesNeeded();
        assertNotNull(result);
    }
}
