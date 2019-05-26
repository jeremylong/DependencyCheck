SET REFERENTIAL_INTEGRITY FALSE;
TRUNCATE TABLE reference;
TRUNCATE TABLE vulnerability;
TRUNCATE TABLE software;
TRUNCATE TABLE cpeEntry;
SET REFERENTIAL_INTEGRITY TRUE;


ALTER TABLE vulnerability ALTER COLUMN cvssScore RENAME TO cvssV2Score;
ALTER TABLE vulnerability ALTER COLUMN cvssAccessVector RENAME TO cvssV2AccessVector;
ALTER TABLE vulnerability ALTER COLUMN cvssAccessComplexity RENAME TO cvssV2AccessComplexity;
ALTER TABLE vulnerability ALTER COLUMN cvssAuthentication RENAME TO cvssV2Authentication;
ALTER TABLE vulnerability ALTER COLUMN cvssConfidentialityImpact RENAME TO cvssV2ConfidentialityImpact;
ALTER TABLE vulnerability ALTER COLUMN cvssIntegrityImpact RENAME TO cvssV2IntegrityImpact;
ALTER TABLE vulnerability ALTER COLUMN cvssAvailabilityImpact RENAME TO cvssV2AvailabilityImpact;
ALTER TABLE vulnerability DROP  COLUMN cwe;
ALTER TABLE vulnerability ADD   COLUMN cvssV2Severity VARCHAR(20);
ALTER TABLE vulnerability ADD   COLUMN cvssV3AttackVector VARCHAR(20);
ALTER TABLE vulnerability ADD   COLUMN cvssV3AttackComplexity VARCHAR(20);
ALTER TABLE vulnerability ADD   COLUMN cvssV3PrivilegesRequired VARCHAR(20);
ALTER TABLE vulnerability ADD   COLUMN cvssV3UserInteraction VARCHAR(20);
ALTER TABLE vulnerability ADD   COLUMN cvssV3Scope VARCHAR(20);
ALTER TABLE vulnerability ADD   COLUMN cvssV3ConfidentialityImpact VARCHAR(20);
ALTER TABLE vulnerability ADD   COLUMN cvssV3IntegrityImpact VARCHAR(20);
ALTER TABLE vulnerability ADD   COLUMN cvssV3AvailabilityImpact VARCHAR(20);
ALTER TABLE vulnerability ADD   COLUMN cvssV3BaseScore DECIMAL(3,1);
ALTER TABLE vulnerability ADD   COLUMN cvssV3BaseSeverity VARCHAR(20);


CREATE TABLE cweEntry (cveid INT, cwe VARCHAR(20),
    CONSTRAINT fkCweEntry FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);
CREATE INDEX idxCwe ON cweEntry(cveid);

ALTER TABLE cpeEntry DROP COLUMN cpe;
ALTER TABLE cpeEntry ADD COLUMN version VARCHAR(255);
ALTER TABLE cpeEntry ADD COLUMN update_version VARCHAR(255);
ALTER TABLE cpeEntry ADD COLUMN edition VARCHAR(255);
ALTER TABLE cpeEntry ADD COLUMN lang VARCHAR(20);
ALTER TABLE cpeEntry ADD COLUMN sw_edition VARCHAR(255);
ALTER TABLE cpeEntry ADD COLUMN target_sw VARCHAR(255);
ALTER TABLE cpeEntry ADD COLUMN target_hw VARCHAR(255);
ALTER TABLE cpeEntry ADD COLUMN other VARCHAR(255);
DROP INDEX idxCpeEntry;
CREATE INDEX idxCpeEntry ON cpeEntry(vendor, product, version, update_version, edition, lang, sw_edition, target_sw, target_hw, other);

ALTER TABLE software DROP COLUMN previousversion;
ALTER TABLE software ADD  COLUMN versionEndExcluding VARCHAR(50);
ALTER TABLE software ADD  COLUMN versionEndIncluding VARCHAR(50);
ALTER TABLE software ADD  COLUMN versionStartExcluding VARCHAR(50);
ALTER TABLE software ADD  COLUMN versionStartIncluding VARCHAR(50);
ALTER TABLE software ADD  COLUMN vulnerable BOOLEAN;


DELETE FROM properties WHERE ID like 'NVD CVE%';
UPDATE Properties SET value='4.0' WHERE ID='version';