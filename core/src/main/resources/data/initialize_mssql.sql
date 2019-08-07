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
if exists (SELECT 1 FROM sysobjects WHERE name='cweEntry' AND xtype='U')
	drop table cweEntry
	
CREATE TABLE vulnerability (id int identity(1,1) PRIMARY KEY, cve VARCHAR(20) UNIQUE,
	description VARCHAR(8000), cvssV2Score DECIMAL(3,1), cvssV2AccessVector VARCHAR(20),
	cvssV2AccessComplexity VARCHAR(20), cvssV2Authentication VARCHAR(20), cvssV2ConfidentialityImpact VARCHAR(20),
	cvssV2IntegrityImpact VARCHAR(20), cvssV2AvailabilityImpact VARCHAR(20), cvssV2Severity VARCHAR(20),
        cvssV3AttackVector VARCHAR(20), cvssV3AttackComplexity VARCHAR(20), cvssV3PrivilegesRequired VARCHAR(20),
        cvssV3UserInteraction VARCHAR(20), cvssV3Scope VARCHAR(20), cvssV3ConfidentialityImpact VARCHAR(20),
        cvssV3IntegrityImpact VARCHAR(20), cvssV3AvailabilityImpact VARCHAR(20), cvssV3BaseScore DECIMAL(3,1), 
        cvssV3BaseSeverity VARCHAR(20));

CREATE TABLE reference (cveid INT, name VARCHAR(1000), url VARCHAR(1000), source VARCHAR(255),
	CONSTRAINT FK_Reference FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEntry (id INT identity(1,1) PRIMARY KEY, part CHAR(1), vendor VARCHAR(255), product VARCHAR(255),
version VARCHAR(255), update_version VARCHAR(255), edition VARCHAR(255), lang VARCHAR(20), sw_edition VARCHAR(255), 
target_sw VARCHAR(255), target_hw VARCHAR(255), other VARCHAR(255), ecosystem VARCHAR(255));

CREATE TABLE software (cveid INT, cpeEntryId INT, versionEndExcluding VARCHAR(50), versionEndIncluding VARCHAR(50), 
                       versionStartExcluding VARCHAR(50), versionStartIncluding VARCHAR(50), vulnerable BIT
    , CONSTRAINT FK_SoftwareCve FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
    , CONSTRAINT FK_SoftwareCpeProduct FOREIGN KEY (cpeEntryId) REFERENCES cpeEntry(id));

CREATE TABLE cweEntry (cveid INT, cwe VARCHAR(20)
    , CONSTRAINT FK_CweEntry FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
    , PRIMARY KEY (cveid, cwe));

CREATE INDEX idxCwe ON cweEntry(cveid);
CREATE INDEX idxVulnerability ON vulnerability(cve);
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxCpe ON cpeEntry(vendor, product);
CREATE INDEX idxSoftwareCve ON software(cveid);
CREATE INDEX idxSoftwareCpe ON software(cpeEntryId);

#on mssql we cannot index all columns due to key length issues
CREATE INDEX idxCpeEntry ON cpeEntry(part, vendor, product, version);
#, update_version, edition, lang, sw_edition, target_sw, target_hw, other);

CREATE TABLE properties (id varchar(50) PRIMARY KEY, value varchar(500));
INSERT INTO properties(id,value) VALUES ('version','4.1');