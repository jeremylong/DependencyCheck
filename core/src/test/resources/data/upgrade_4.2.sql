ALTER TABLE vulnerability ALTER COLUMN cvssV2Severity RENAME TO v2Severity;
ALTER TABLE vulnerability ALTER COLUMN cvssV2Score RENAME TO v2Score;
ALTER TABLE vulnerability ALTER COLUMN cvssV2AccessVector RENAME TO v2AccessVector;
ALTER TABLE vulnerability ALTER COLUMN cvssV2AccessComplexity RENAME TO v2AccessComplexity;
ALTER TABLE vulnerability ALTER COLUMN cvssV2Authentication RENAME TO v2Authentication;
ALTER TABLE vulnerability ALTER COLUMN cvssV2ConfidentialityImpact RENAME TO v2ConfidentialityImpact;
ALTER TABLE vulnerability ALTER COLUMN cvssV2IntegrityImpact RENAME TO v2IntegrityImpact;
ALTER TABLE vulnerability ALTER COLUMN cvssV2AvailabilityImpact RENAME TO v2AvailabilityImpact;
ALTER TABLE vulnerability ALTER COLUMN cvssV3AttackVector RENAME TO v3AttackVector;
ALTER TABLE vulnerability ALTER COLUMN cvssV3AttackComplexity RENAME TO v3AttackComplexity;
ALTER TABLE vulnerability ALTER COLUMN cvssV3PrivilegesRequired RENAME TO v3PrivilegesRequired;
ALTER TABLE vulnerability ALTER COLUMN cvssV3UserInteraction RENAME TO v3UserInteraction;
ALTER TABLE vulnerability ALTER COLUMN cvssV3Scope RENAME TO v3Scope;
ALTER TABLE vulnerability ALTER COLUMN cvssV3ConfidentialityImpact RENAME TO v3ConfidentialityImpact;
ALTER TABLE vulnerability ALTER COLUMN cvssV3IntegrityImpact RENAME TO v3IntegrityImpact;
ALTER TABLE vulnerability ALTER COLUMN cvssV3AvailabilityImpact RENAME TO v3AvailabilityImpact;
ALTER TABLE vulnerability ALTER COLUMN cvssV3BaseScore RENAME TO v3BaseScore;
ALTER TABLE vulnerability ALTER COLUMN cvssV3BaseSeverity RENAME TO v3BaseSeverity;
ALTER TABLE vulnerability ADD   COLUMN v2ExploitabilityScore DECIMAL(3,1);
ALTER TABLE vulnerability ADD   COLUMN v2ImpactScore DECIMAL(3,1);
ALTER TABLE vulnerability ADD   COLUMN v2AcInsufInfo BOOLEAN;
ALTER TABLE vulnerability ADD   COLUMN v2ObtainAllPrivilege BOOLEAN;
ALTER TABLE vulnerability ADD   COLUMN v2ObtainUserPrivilege BOOLEAN;
ALTER TABLE vulnerability ADD   COLUMN v2ObtainOtherPrivilege BOOLEAN;
ALTER TABLE vulnerability ADD   COLUMN v2UserInteractionRequired BOOLEAN;
ALTER TABLE vulnerability ADD   COLUMN v2Version VARCHAR(5);
ALTER TABLE vulnerability ADD   COLUMN v3ExploitabilityScore DECIMAL(3,1);
ALTER TABLE vulnerability ADD   COLUMN v3ImpactScore DECIMAL(3,1);
ALTER TABLE vulnerability ADD   COLUMN v3Version VARCHAR(5);

CREATE TABLE cpeEcosystemCache (vendor VARCHAR(255), product VARCHAR(255), ecosystem VARCHAR(255), PRIMARY KEY (vendor, product));
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('apache', 'zookeeper', 'MULTIPLE');

CREATE ALIAS update_vulnerability FOR "org.owasp.dependencycheck.data.nvdcve.H2Functions.updateVulnerability";
CREATE ALIAS insert_software FOR "org.owasp.dependencycheck.data.nvdcve.H2Functions.insertSoftware";

UPDATE Properties SET `value`='5.0' WHERE ID='version';
