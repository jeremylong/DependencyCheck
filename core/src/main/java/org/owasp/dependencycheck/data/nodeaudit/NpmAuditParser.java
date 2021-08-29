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
 * Copyright (c) 2018 Steve Springett. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nodeaudit;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.json.JSONException;

/**
 * Parser for NPM Audit API response. This parser is derived from:
 * https://github.com/DependencyTrack/dependency-track/blob/master/src/main/java/org/owasp/dependencytrack/parser/npm/audit/NpmAuditParser.java
 *
 * @author Steve Springett
 */
public class NpmAuditParser {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(NpmAuditParser.class);

    /**
     * Parses the JSON response from the NPM Audit API.
     *
     * @param jsonResponse the JSON node to parse
     * @return an AdvisoryResults object
     * @throws org.json.JSONException thrown if the JSON is not of the expected
     * schema
     */
    public List<Advisory> parse(JSONObject jsonResponse) throws JSONException {
        LOGGER.debug("Parsing JSON node");
        final List<Advisory> advisories = new ArrayList<>();
        final JSONObject jsonAdvisories = jsonResponse.getJSONObject("advisories");
        final Iterator<?> keys = jsonAdvisories.keys();
        while (keys.hasNext()) {
            final String key = (String) keys.next();
            final Advisory advisory = parseAdvisory(jsonAdvisories.getJSONObject(key));
            advisories.add(advisory);
        }
        return advisories;
    }

    /**
     * Parses the advisory from Node Audit.
     *
     * @param object the JSON object containing the advisory
     * @return the Advisory object
     * @throws org.json.JSONException thrown if the JSON is not of the expected
     * schema
     */
    private Advisory parseAdvisory(JSONObject object) throws JSONException {
        final Advisory advisory = new Advisory();
        advisory.setId(object.getInt("id"));
        advisory.setOverview(object.optString("overview", null));
        advisory.setReferences(object.optString("references", null));
        advisory.setCreated(object.optString("created", null));
        advisory.setUpdated(object.optString("updated", null));
        advisory.setRecommendation(object.optString("recommendation", null));
        advisory.setTitle(object.optString("title", null));
        //advisory.setFoundBy(object.optString("author", null));
        //advisory.setReportedBy(object.optString("author", null));
        advisory.setModuleName(object.optString("module_name", null));
        advisory.setVulnerableVersions(object.optString("vulnerable_versions", null));
        advisory.setPatchedVersions(object.optString("patched_versions", null));
        advisory.setAccess(object.optString("access", null));
        advisory.setSeverity(object.optString("severity", null));
        advisory.setCwe(object.optString("cwe", null));

        final JSONArray findings = object.optJSONArray("findings");
        for (int i = 0; i < findings.length(); i++) {
            final JSONObject finding = findings.getJSONObject(i);
            final String version = finding.optString("version", null);
            final JSONArray paths = finding.optJSONArray("paths");
            for (int j = 0; j < paths.length(); j++) {
                final String path = paths.getString(j);
                if (path != null && path.equals(advisory.getModuleName())) {
                    advisory.setVersion(version);
                }
            }
        }

        final JSONArray jsonCves = object.optJSONArray("cves");
        final List<String> stringCves = new ArrayList<>();
        if (jsonCves != null) {
            for (int j = 0; j < jsonCves.length(); j++) {
                stringCves.add(jsonCves.getString(j));
            }
            advisory.setCves(stringCves);
        }
        return advisory;
    }
}
