/*
 * This file is part of DependencyCheck.
 *
 * DependencyCheck is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * DependencyCheck is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * DependencyCheck. If not, see http://www.gnu.org/licenses/.
 *
 * Copyright (c) 2012 Jeremy Long. All Rights Reserved.
 */
package org.codesecure.dependencycheck.data.lucene;

/**
 * VersionAnalyzer is a Lucene Analyzer used to analyze version information.
 *
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class VersionAnalyzer {
    //TODO Implement this...
    // use custom attributes for major, minor, x, x, x, rcx
    // these can then be used to weight the score for searches on the version.
    // see http://lucene.apache.org/core/3_6_1/api/core/org/apache/lucene/analysis/package-summary.html#package_description
    // look at this article to implement
    // http://www.codewrecks.com/blog/index.php/2012/08/25/index-your-blog-using-tags-and-lucene-net/
}
