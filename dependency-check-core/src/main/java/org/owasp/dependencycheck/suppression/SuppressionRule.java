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
package org.owasp.dependencycheck.suppression;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Identifier;
import org.owasp.dependencycheck.dependency.Vulnerability;

/**
 *
 * @author Jeremy Long <jeremy.long@owasp.org>
 */
public class SuppressionRule {

    /**
     * The file path for the suppression.
     */
    private PropertyType filePath;

    /**
     * Get the value of filePath.
     *
     * @return the value of filePath
     */
    public PropertyType getFilePath() {
        return filePath;
    }

    /**
     * Set the value of filePath.
     *
     * @param filePath new value of filePath
     */
    public void setFilePath(PropertyType filePath) {
        this.filePath = filePath;
    }
    /**
     * The sha1 hash.
     */
    private String sha1;

    /**
     * Get the value of sha1.
     *
     * @return the value of sha1
     */
    public String getSha1() {
        return sha1;
    }

    /**
     * Set the value of sha1.
     *
     * @param sha1 new value of sha1
     */
    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }
    /**
     * A list of CPEs to suppression
     */
    private List<PropertyType> cpe = new ArrayList<PropertyType>();

    /**
     * Get the value of cpe.
     *
     * @return the value of cpe
     */
    public List<PropertyType> getCpe() {
        return cpe;
    }

    /**
     * Set the value of cpe.
     *
     * @param cpe new value of cpe
     */
    public void setCpe(List<PropertyType> cpe) {
        this.cpe = cpe;
    }

    /**
     * Adds the cpe to the cpe list.
     *
     * @param cpe the cpe to add
     */
    public void addCpe(PropertyType cpe) {
        this.cpe.add(cpe);
    }

    /**
     * Returns whether or not this suppression rule as CPE entries.
     *
     * @return whether or not this suppression rule as CPE entries
     */
    public boolean hasCpe() {
        return cpe.size() > 0;
    }
    /**
     * The list of cvssBelow scores.
     */
    private List<Float> cvssBelow = new ArrayList<Float>();

    /**
     * Get the value of cvssBelow.
     *
     * @return the value of cvssBelow
     */
    public List<Float> getCvssBelow() {
        return cvssBelow;
    }

    /**
     * Set the value of cvssBelow.
     *
     * @param cvssBelow new value of cvssBelow
     */
    public void setCvssBelow(List<Float> cvssBelow) {
        this.cvssBelow = cvssBelow;
    }

    /**
     * Adds the cvss to the cvssBelow list.
     *
     * @param cvss the cvss to add
     */
    public void addCvssBelow(Float cvss) {
        this.cvssBelow.add(cvss);
    }

    /**
     * Returns whether or not this suppression rule has cvss suppressions.
     *
     * @return whether or not this suppression rule has cvss suppressions
     */
    public boolean hasCvssBelow() {
        return cvssBelow.size() > 0;
    }
    /**
     * The list of cwe entries to suppress.
     */
    private List<String> cwe = new ArrayList<String>();

    /**
     * Get the value of cwe.
     *
     * @return the value of cwe
     */
    public List<String> getCwe() {
        return cwe;
    }

    /**
     * Set the value of cwe.
     *
     * @param cwe new value of cwe
     */
    public void setCwe(List<String> cwe) {
        this.cwe = cwe;
    }

    /**
     * Adds the cwe to the cwe list.
     *
     * @param cwe the cwe to add
     */
    public void addCwe(String cwe) {
        this.cwe.add(cwe);
    }

    /**
     * Returns whether this suppression rule has CWE entries.
     *
     * @return whether this suppression rule has CWE entries
     */
    public boolean hasCwe() {
        return cwe.size() > 0;
    }
    /**
     * The list of cve entries to suppress.
     */
    private List<String> cve = new ArrayList<String>();

    /**
     * Get the value of cve.
     *
     * @return the value of cve
     */
    public List<String> getCve() {
        return cve;
    }

    /**
     * Set the value of cve.
     *
     * @param cve new value of cve
     */
    public void setCve(List<String> cve) {
        this.cve = cve;
    }

    /**
     * Adds the cve to the cve list.
     *
     * @param cve the cve to add
     */
    public void addCve(String cve) {
        this.cve.add(cve);
    }

    /**
     * Returns whether this suppression rule has CVE entries.
     *
     * @return whether this suppression rule has CVE entries
     */
    public boolean hasCve() {
        return cve.size() > 0;
    }
    /**
     * A Maven GAV to suppression.
     */
    private PropertyType gav = null;

    /**
     * Get the value of Maven GAV.
     *
     * @return the value of gav
     */
    public PropertyType getGav() {
        return gav;
    }

    /**
     * Set the value of Maven GAV.
     *
     * @param gav new value of Maven gav
     */
    public void setGav(PropertyType gav) {
        this.gav = gav;
    }

    /**
     * Returns whether or not this suppression rule as GAV entries.
     *
     * @return whether or not this suppression rule as GAV entries
     */
    public boolean hasGav() {
        return gav != null;
    }

    /**
     * Processes a given dependency to determine if any CPE, CVE, CWE, or CVSS scores should be suppressed. If any
     * should be, they are removed from the dependency.
     *
     * @param dependency a project dependency to analyze
     */
    public void process(Dependency dependency) {
        if (filePath != null && !filePath.matches(dependency.getFilePath())) {
            return;
        }
        if (sha1 != null && !sha1.equalsIgnoreCase(dependency.getSha1sum())) {
            return;
        }
        if (gav != null) {
            final Iterator<Identifier> itr = dependency.getIdentifiers().iterator();
            boolean gavFound = false;
            while (itr.hasNext()) {
                final Identifier i = itr.next();
                if (identifierMatches("maven", this.gav, i)) {
                    gavFound = true;
                    break;
                }
            }
            if (!gavFound) {
                return;
            }
        }

        if (this.hasCpe()) {
            final Iterator<Identifier> itr = dependency.getIdentifiers().iterator();
            while (itr.hasNext()) {
                final Identifier i = itr.next();
                for (PropertyType c : this.cpe) {
                    if (identifierMatches("cpe", c, i)) {
                        dependency.addSuppressedIdentifier(i);
                        itr.remove();
                        break;
                    }
                }
            }
        }
        if (hasCve() || hasCwe() || hasCvssBelow()) {
            final Iterator<Vulnerability> itr = dependency.getVulnerabilities().iterator();
            while (itr.hasNext()) {
                boolean remove = false;
                final Vulnerability v = itr.next();
                for (String entry : this.cve) {
                    if (entry.equalsIgnoreCase(v.getName())) {
                        remove = true;
                        break;
                    }
                }
                if (!remove) {
                    for (String entry : this.cwe) {
                        if (v.getCwe() != null) {
                            final String toMatch = String.format("CWE-%s ", entry);
                            final String toTest = v.getCwe().substring(0, toMatch.length()).toUpperCase();
                            if (toTest.equals(toMatch)) {
                                remove = true;
                                break;
                            }
                        }
                    }
                }
                if (!remove) {
                    for (float cvss : this.cvssBelow) {
                        if (v.getCvssScore() < cvss) {
                            remove = true;
                            break;
                        }
                    }
                }
                if (remove) {
                    dependency.addSuppressedVulnerability(v);
                    itr.remove();
                }
            }
        }
    }

    /**
     * Identifies if the cpe specified by the cpe suppression rule does not specify a version.
     *
     * @param c a suppression rule identifier
     * @return true if the property type does not specify a version; otherwise false
     */
    boolean cpeHasNoVersion(PropertyType c) {
        if (c.isRegex()) {
            return false;
        }
        if (countCharacter(c.getValue(), ':') == 3) {
            return true;
        }
        return false;
    }

    /**
     * Counts the number of occurrences of the character found within the string.
     *
     * @param str the string to check
     * @param c the character to count
     * @return the number of times the character is found in the string
     */
    int countCharacter(String str, char c) {
        int count = 0;
        int pos = str.indexOf(c) + 1;
        while (pos > 0) {
            count += 1;
            pos = str.indexOf(c, pos) + 1;
        }
        return count;
    }

    /**
     * Determines if the cpeEntry specified as a PropertyType matches the given Identifier.
     *
     * @param identifierType the type of identifier ("cpe", "maven", etc.)
     * @param suppressionEntry a suppression rule entry
     * @param identifier a CPE identifier to check
     * @return true if the entry matches; otherwise false
     */
    boolean identifierMatches(String identifierType, PropertyType suppressionEntry, Identifier identifier) {
        if (identifierType.equals(identifier.getType())) {
            if (suppressionEntry.matches(identifier.getValue())) {
                return true;
            } else if ("cpe".equals(identifierType) && cpeHasNoVersion(suppressionEntry)) {
                if (suppressionEntry.isCaseSensitive()) {
                    return identifier.getValue().startsWith(suppressionEntry.getValue());
                } else {
                    final String id = identifier.getValue().toLowerCase();
                    final String check = suppressionEntry.getValue().toLowerCase();
                    return id.startsWith(check);
                }
            }
        }
        return false;
    }

    /**
     * Standard toString implementation.
     *
     * @return a string representation of this object
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("SuppressionRule{");
        if (filePath != null) {
            sb.append("filePath=").append(filePath).append(",");
        }
        if (sha1 != null) {
            sb.append("sha1=").append(sha1).append(",");
        }
        if (gav != null) {
            sb.append("gav=").append(gav).append(",");
        }
        if (cpe != null && cpe.size() > 0) {
            sb.append("cpe={");
            for (PropertyType pt : cpe) {
                sb.append(pt).append(",");
            }
            sb.append("}");
        }
        if (cwe != null && cwe.size() > 0) {
            sb.append("cwe={");
            for (String s : cwe) {
                sb.append(s).append(",");
            }
            sb.append("}");
        }
        if (cve != null && cve.size() > 0) {
            sb.append("cve={");
            for (String s : cve) {
                sb.append(s).append(",");
            }
            sb.append("}");
        }
        if (cvssBelow != null && cvssBelow.size() > 0) {
            sb.append("cvssBelow={");
            for (Float s : cvssBelow) {
                sb.append(s).append(",");
            }
            sb.append("}");
        }
        sb.append("}");
        return sb.toString();
    }
}
