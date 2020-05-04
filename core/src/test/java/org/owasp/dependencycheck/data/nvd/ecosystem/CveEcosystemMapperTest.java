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
 * Copyright (c) 2020 The OWASP Foundation. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.nvd.ecosystem;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import static org.junit.Assert.*;
import org.owasp.dependencycheck.analyzer.JarAnalyzer;
import org.owasp.dependencycheck.data.nvd.json.CVEJSON40Min11;
import org.owasp.dependencycheck.data.nvd.json.DefConfigurations;
import org.owasp.dependencycheck.data.nvd.json.DefCpeMatch;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.DefNode;
import org.owasp.dependencycheck.data.nvd.json.Description;
import org.owasp.dependencycheck.data.nvd.json.LangString;

/**
 *
 * @author Jeremy Long
 */
public class CveEcosystemMapperTest {

    /**
     * Test of getEcosystem method, of class CveEcosystemMapper.
     */
    @Test
    public void testGetEcosystem() {
        CveEcosystemMapper mapper = new CveEcosystemMapper();
        String value = "There is a vulnerability in some.java file";
        assertEquals(JarAnalyzer.DEPENDENCY_ECOSYSTEM, mapper.getEcosystem(asCve(value)));
        assertNull(mapper.getEcosystem(asCve(value,"cpe:2.3:a:apache:struts:1.2.1:*:*:*:*:*:*:*")));
    }

    private DefCveItem asCve(String description, String... cpe) {
        DefCveItem defCveItem = new DefCveItem();

        Description d = new Description();

        LangString string = new LangString();
        string.setLang("en");
        string.setValue(description);

        d.getDescriptionData().add(string);

        CVEJSON40Min11 cve = new CVEJSON40Min11();
        cve.setDescription(d);

        defCveItem.setCve(cve);

        final DefConfigurations configurations = new DefConfigurations();
        final DefNode node = new DefNode();
        final List<DefCpeMatch> matches = new ArrayList<>();
        final DefCpeMatch m = new DefCpeMatch();
        m.setCpe23Uri("cpe:2.3:a:owasp:dependency-check:5.0.0:*:*:*:*:*:*:*");
        matches.add(m);
        for (String s : cpe) {
            final DefCpeMatch cpeMatch = new DefCpeMatch();
            cpeMatch.setCpe23Uri(s);
            matches.add(cpeMatch);
        }
        node.setCpeMatch(matches);
        List<DefNode> nodes = new ArrayList<>();
        nodes.add(node);
        configurations.setNodes(nodes);

        defCveItem.setConfigurations(configurations);

        return defCveItem;
    }
}
