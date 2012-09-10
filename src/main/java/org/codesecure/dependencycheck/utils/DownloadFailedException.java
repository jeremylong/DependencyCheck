/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.codesecure.dependencycheck.utils;

import java.io.IOException;

/**
 * 
 * @author Jeremy Long (jeremy.long@gmail.com)
 */
public class DownloadFailedException extends IOException {
    
    private static final long serialVersionUID = 1L;
    
    public DownloadFailedException() {
        super();
    }
    
    public DownloadFailedException(String msg) {
        super(msg);
    }
    public DownloadFailedException(Throwable ex) {
        super(ex);
    }
    public DownloadFailedException(String msg, Throwable ex) {
        super(msg,ex);
    }
}
