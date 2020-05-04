package org.owasp.dependencycheck.data.artifactory;

import java.util.Date;

/**
 * Copied from JFrog's artifactory client.
 *
 * @see
 * <a href="https://github.com/jfrog/artifactory-client-java">artifactory-client-java</a>
 *
 * @author jbaruch
 * @since 29/07/12
 */
public class FileImpl extends ItemImpl {

    private String downloadUri;
    private Date created;
    private String createdBy;
    private long size;
    private String mimeType;
    private ChecksumsImpl checksums;
    private ChecksumsImpl originalChecksums;
    private String remoteUrl;

    public boolean isFolder() {
        return false;
    }

    public Date getCreated() {
        return new Date(created.getTime());
    }

    public void setCreated(Date created) {
        this.created = new Date(created.getTime());
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public String getDownloadUri() {
        return downloadUri;
    }

    public void setDownloadUri(String downloadUri) {
        this.downloadUri = downloadUri;
    }

    public String getMimeType() {
        return mimeType;
    }

    public void setMimeType(String mimeType) {
        this.mimeType = mimeType;
    }

    public long getSize() {
        return size;
    }

    public void setSize(long size) {
        this.size = size;
    }

    public ChecksumsImpl getChecksums() {
        return checksums;
    }

    public void setChecksums(ChecksumsImpl checksums) {
        this.checksums = checksums;
    }

    public ChecksumsImpl getOriginalChecksums() {
        return originalChecksums;
    }

    public void setOriginalChecksums(ChecksumsImpl originalChecksums) {
        this.originalChecksums = originalChecksums;
    }

    public String getRemoteUrl() {
        return remoteUrl;
    }

    public void setRemoteUrl(String remoteUrl) {
        this.remoteUrl = remoteUrl;
    }
}
