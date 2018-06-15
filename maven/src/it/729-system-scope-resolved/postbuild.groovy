/*
 * This file is part of dependency-check-maven.
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
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import java.nio.charset.Charset;
import groovy.json.JsonSlurper;

def slurper = new JsonSlurper()
def json = slurper.parse(new File(basedir, "target/dependency-check-report.json"), "UTF-8")

assert json instanceof Map
assert json.dependencies instanceof List
//this could be 1 or 4 dependeing on the JVM used. In some cases JavaScript is embedded in com.sun.tools.
assert (json.dependencies.size()==4 || json.dependencies.size()==1)
return true;
