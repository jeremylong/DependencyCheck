/*
 * Copyright 2014 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.owasp.dependencycheck.data.update;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Properties;
import mockit.Mock;
import mockit.MockUp;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.owasp.dependencycheck.BaseTest;
import org.owasp.dependencycheck.data.nvdcve.DatabaseProperties;
import org.owasp.dependencycheck.data.update.exception.UpdateException;
import org.owasp.dependencycheck.utils.DependencyVersion;

/**
 *
 * @author Jeremy Long
 */
public class EngineVersionCheckTest extends BaseTest {

//    /**
//     * Test of update method, of class EngineVersionCheck.
//     */
//    @Test
//    public void testUpdate() throws Exception {
//        EngineVersionCheck instance = new EngineVersionCheck();
//        instance.update();
//    }
    private long getEpoch(String date) {
        return DateTime.parse(date).toInstant().getMillis() / 1000;
    }

    /**
     * Test of shouldUpdate method, of class EngineVersionCheck.
     */
    @Test
    public void testShouldUpdate() throws Exception {
        DatabaseProperties properties = new MockUp<DatabaseProperties>() {
            final private Properties properties = new Properties();

            @Mock
            public void save(String key, String value) throws UpdateException {
                properties.setProperty(key, value);
            }

            @Mock
            public String getProperty(String key) {
                return properties.getProperty(key);
            }

        }.getMockInstance();

        String updateToVersion = "1.2.6";
        String currentVersion = "1.2.6";

        long lastChecked = getEpoch("2014-12-01");
        long now = getEpoch("2014-12-01");

        EngineVersionCheck instance = new EngineVersionCheck();
        boolean expResult = false;
        instance.setUpdateToVersion(updateToVersion);
        boolean result = instance.shouldUpdate(lastChecked, now, properties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "1.2.5";
        currentVersion = "1.2.5";
        lastChecked = getEpoch("2014-10-01");
        now = getEpoch("2014-12-01");
        expResult = true;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, properties, currentVersion);
        assertEquals(expResult, result);
        //System.out.println(properties.getProperty(CURRENT_ENGINE_RELEASE));

        updateToVersion = "1.2.5";
        currentVersion = "1.2.5";
        lastChecked = getEpoch("2014-12-01");
        now = getEpoch("2014-12-03");
        expResult = false;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, properties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "1.2.6";
        currentVersion = "1.2.5";
        lastChecked = getEpoch("2014-12-01");
        now = getEpoch("2014-12-03");
        expResult = true;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, properties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "1.2.5";
        currentVersion = "1.2.6";
        lastChecked = getEpoch("2014-12-01");
        now = getEpoch("2014-12-08");
        expResult = false;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, properties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "";
        currentVersion = "1.2.5";
        lastChecked = getEpoch("2014-12-01");
        now = getEpoch("2014-12-03");
        expResult = false;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, properties, currentVersion);
        assertEquals(expResult, result);

        updateToVersion = "";
        currentVersion = "1.2.5";
        lastChecked = getEpoch("2014-12-01");
        now = getEpoch("2015-12-08");
        expResult = true;
        instance.setUpdateToVersion(updateToVersion);
        result = instance.shouldUpdate(lastChecked, now, properties, currentVersion);
        assertEquals(expResult, result);
    }

    /**
     * Test of getCurrentReleaseVersion method, of class EngineVersionCheck.
     */
    @Test
    public void testGetCurrentReleaseVersion() {
        EngineVersionCheck instance = new EngineVersionCheck();
        DependencyVersion minExpResult = new DependencyVersion("1.2.6");
        String release = instance.getCurrentReleaseVersion();
        DependencyVersion result = new DependencyVersion(release);
        assertTrue(minExpResult.compareTo(result) <= 0);
    }
}
