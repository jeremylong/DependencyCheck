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
package org.owasp.dependencycheck.data.nvdcve;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.collections.map.ReferenceMap;
import org.owasp.dependencycheck.dependency.Vulnerability;
import org.owasp.dependencycheck.dependency.VulnerableSoftware;
import org.owasp.dependencycheck.utils.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.stream.Collectors;

import static org.apache.commons.collections.map.AbstractReferenceMap.HARD;
import static org.apache.commons.collections.map.AbstractReferenceMap.SOFT;
import org.owasp.dependencycheck.analyzer.exception.LambdaExceptionWrapper;
import org.owasp.dependencycheck.analyzer.exception.UnexpectedAnalysisException;
import org.owasp.dependencycheck.models.VulnerabilityDTO;
import org.owasp.dependencycheck.data.nvd.json.BaseMetricV2;
import org.owasp.dependencycheck.data.nvd.json.BaseMetricV3;
import org.owasp.dependencycheck.data.nvd.json.CpeMatchStreamCollector;
import org.owasp.dependencycheck.data.nvd.json.DefCpeMatch;
import org.owasp.dependencycheck.data.nvd.json.DefCveItem;
import org.owasp.dependencycheck.data.nvd.json.LangString;
import org.owasp.dependencycheck.data.nvd.json.NodeFlatteningCollector;
import org.owasp.dependencycheck.data.nvd.json.ProblemtypeDatum;
import org.owasp.dependencycheck.data.nvd.json.Reference;
import static org.owasp.dependencycheck.data.nvdcve.CveDB.PreparedStatementCveDb.*;
import org.owasp.dependencycheck.data.update.cpe.CpePlus;
import org.owasp.dependencycheck.dependency.CvssV2;
import org.owasp.dependencycheck.dependency.CvssV3;
import org.owasp.dependencycheck.dependency.VulnerableSoftwareBuilder;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeBuilder;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.exceptions.CpeValidationException;


public interface ICveDBWrapper {
    public Vulnerability getVulnerability(String reference); // cveDatabase.getVulnerability(vp.getCveReference());
    public List<VulnerabilityDTO> getPerlVulnerabilities(); // cveDatabase.getPerlVulnerabilities();
}
