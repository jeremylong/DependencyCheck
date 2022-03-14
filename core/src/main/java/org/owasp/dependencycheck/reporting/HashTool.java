package org.owasp.dependencycheck.reporting;

import org.apache.commons.codec.digest.DigestUtils;

import javax.annotation.concurrent.ThreadSafe;

/**
 * An extremely simple wrapper around hashing functionality
 *
 * @author Tim Dodd
 */
@ThreadSafe
public class HashTool {
    
    public String md5Hex(String text) {
        return DigestUtils.md5Hex(text);
    }
}
