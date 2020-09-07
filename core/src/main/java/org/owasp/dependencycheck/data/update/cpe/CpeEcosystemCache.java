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
 * Copyright (c) 2020 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.update.cpe;

import com.google.common.base.Strings;
import java.util.HashMap;
import java.util.Map;
import org.owasp.dependencycheck.data.update.nvd.NvdCveParser;
import org.owasp.dependencycheck.utils.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Jeremy Long
 */
public final class CpeEcosystemCache {

    private final static String MULTIPLE_ECOSYSTEMS_IDENTIFIED = "MULTIPLE";
    private static Map<Pair<String, String>, String> cache = new HashMap<>();
    private static Map<Pair<String, String>, String> changed = new HashMap<>();

    private CpeEcosystemCache() {
        //empty constructor for utiilty class
    }
    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NvdCveParser.class);
    
    public static synchronized String getEcosystem(String vendor, String product, String identifiedEcosystem) {
        Pair<String, String> key = new Pair<>(vendor, product);
        String current = cache.get(key);
        String result = null;
        if (current == null) {
            if (!Strings.isNullOrEmpty(identifiedEcosystem)) {
                cache.put(key, identifiedEcosystem);
                changed.put(key, identifiedEcosystem);
                result = identifiedEcosystem;
            }
        } else if (MULTIPLE_ECOSYSTEMS_IDENTIFIED.equals(current)) {
            //do nothing - result is already null
        } else if (current.equals(identifiedEcosystem) || identifiedEcosystem == null) {
            result = current;
        } else {
            cache.put(key, MULTIPLE_ECOSYSTEMS_IDENTIFIED);
            changed.put(key, MULTIPLE_ECOSYSTEMS_IDENTIFIED);
        }
        return result;
    }

    public static synchronized void setCache(Map<Pair<String, String>, String> cache) {
        CpeEcosystemCache.cache = cache;
        CpeEcosystemCache.changed = new HashMap<>();
    }

    public static synchronized Map<Pair<String, String>, String> getChanged() {
        return CpeEcosystemCache.changed;
    }

    public static synchronized boolean isEmpty() {
        return CpeEcosystemCache.cache.isEmpty();
    }
}
