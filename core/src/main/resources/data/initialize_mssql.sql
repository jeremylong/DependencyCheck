if exists (SELECT 1 FROM sysobjects WHERE name='software' AND xtype='U')
	drop table software
if exists (SELECT 1 FROM sysobjects WHERE name='cpeEntry' AND xtype='U')
	drop table cpeEntry
if exists (SELECT 1 FROM sysobjects WHERE name='reference' AND xtype='U')
	drop table reference
if exists (SELECT 1 FROM sysobjects WHERE name='vulnerability' AND xtype='U')
	drop table vulnerability
if exists (SELECT 1 FROM sysobjects WHERE name='properties' AND xtype='U')
	drop table properties

CREATE TABLE properties (id varchar(50) PRIMARY KEY, value varchar(500));

CREATE TABLE vulnerability (id int identity(1,1) PRIMARY KEY, cve VARCHAR(20) UNIQUE,
	description VARCHAR(8000), cwe VARCHAR(10), cvssScore DECIMAL(3,1), cvssAccessVector VARCHAR(20),
	cvssAccessComplexity VARCHAR(20), cvssAuthentication VARCHAR(20), cvssConfidentialityImpact VARCHAR(20),
	cvssIntegrityImpact VARCHAR(20), cvssAvailabilityImpact VARCHAR(20));

CREATE TABLE reference (cveid INT, name VARCHAR(1000), url VARCHAR(1000), source VARCHAR(255),
	CONSTRAINT FK_Reference FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEntry (id INT identity(1,1) PRIMARY KEY, cpe VARCHAR(250), vendor VARCHAR(255), product VARCHAR(255));

CREATE TABLE software (cveid INT, cpeEntryId INT, previousVersion VARCHAR(50)
    , CONSTRAINT FK_SoftwareCve FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
    , CONSTRAINT FK_SoftwareCpeProduct FOREIGN KEY (cpeEntryId) REFERENCES cpeEntry(id)
    , PRIMARY KEY (cveid, cpeEntryId));

CREATE INDEX idxVulnerability ON vulnerability(cve);
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxCpe ON cpeEntry(cpe);
CREATE INDEX idxCpeEntry ON cpeEntry(vendor, product);
CREATE INDEX idxSoftwareCve ON software(cveid);
CREATE INDEX idxSoftwareCpe ON software(cpeEntryId);

INSERT INTO properties(id,value) VALUES ('version','3.0');