--CREATE database dependencycheck;
USE dependencycheck;
GO

if exists (SELECT 1 FROM sysobjects WHERE name='software' AND xtype='U')
	drop table software;
if exists (SELECT 1 FROM sysobjects WHERE name='cpeEntry' AND xtype='U')
	drop table cpeEntry;
if exists (SELECT 1 FROM sysobjects WHERE name='reference' AND xtype='U')
	drop table reference;
if exists (SELECT 1 FROM sysobjects WHERE name='properties' AND xtype='U')
	drop table properties;
if exists (SELECT 1 FROM sysobjects WHERE name='cweEntry' AND xtype='U')
	drop table cweEntry;
if exists (SELECT 1 FROM sysobjects WHERE name='cpeEcosystemCache' AND xtype='U')
	drop table cpeEcosystemCache;
if exists (SELECT 1 FROM sysobjects WHERE name='vulnerability' AND xtype='U')
	drop table vulnerability;
if exists (SELECT 1 FROM sysobjects WHERE name='save_property' AND xtype='P')
	drop procedure save_property;
if exists (SELECT 1 FROM sysobjects WHERE name='merge_ecosystem' AND xtype='P')
	drop procedure merge_ecosystem;
if exists (SELECT 1 FROM sysobjects WHERE name='update_vulnerability' AND xtype='P')
	drop procedure update_vulnerability;
if exists (SELECT 1 FROM sysobjects WHERE name='insert_software' AND xtype='P')
	drop procedure insert_software;    


CREATE TABLE vulnerability (id int identity(1,1) PRIMARY KEY, cve VARCHAR(20) UNIQUE,
	description VARCHAR(8000), v2Severity VARCHAR(20), v2ExploitabilityScore DECIMAL(3,1), 
        v2ImpactScore DECIMAL(3,1), v2AcInsufInfo BIT, v2ObtainAllPrivilege BIT, 
        v2ObtainUserPrivilege BIT, v2ObtainOtherPrivilege BIT, v2UserInteractionRequired BIT, 
        v2Score DECIMAL(3,1), v2AccessVector VARCHAR(20), v2AccessComplexity VARCHAR(20), 
        v2Authentication VARCHAR(20), v2ConfidentialityImpact VARCHAR(20), v2IntegrityImpact VARCHAR(20), 
        v2AvailabilityImpact VARCHAR(20), v2Version VARCHAR(5), v3ExploitabilityScore DECIMAL(3,1), 
        v3ImpactScore DECIMAL(3,1), v3AttackVector VARCHAR(20), v3AttackComplexity VARCHAR(20), 
        v3PrivilegesRequired VARCHAR(20), v3UserInteraction VARCHAR(20), v3Scope VARCHAR(20), 
        v3ConfidentialityImpact VARCHAR(20), v3IntegrityImpact VARCHAR(20), v3AvailabilityImpact VARCHAR(20), 
        v3BaseScore DECIMAL(3,1), v3BaseSeverity VARCHAR(20), v3Version VARCHAR(5));

CREATE TABLE reference (cveid INT, name VARCHAR(1000), url VARCHAR(1000), source VARCHAR(255),
	CONSTRAINT FK_Reference FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE cpeEntry (id INT identity(1,1) PRIMARY KEY, part CHAR(1), vendor VARCHAR(255), product VARCHAR(255),
    version VARCHAR(255), update_version VARCHAR(255), edition VARCHAR(255), lang VARCHAR(20), sw_edition VARCHAR(255), 
    target_sw VARCHAR(255), target_hw VARCHAR(255), other VARCHAR(255), ecosystem VARCHAR(255));

CREATE TABLE software (cveid INT, cpeEntryId INT, versionEndExcluding VARCHAR(60), versionEndIncluding VARCHAR(60), 
                       versionStartExcluding VARCHAR(60), versionStartIncluding VARCHAR(60), vulnerable BIT
    , CONSTRAINT FK_SoftwareCve FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE
    , CONSTRAINT FK_SoftwareCpeProduct FOREIGN KEY (cpeEntryId) REFERENCES cpeEntry(id));

CREATE TABLE cweEntry (cveid INT, cwe VARCHAR(20)
    , CONSTRAINT FK_CweEntry FOREIGN KEY (cveid) REFERENCES vulnerability(id) ON DELETE CASCADE);

CREATE TABLE properties (id varchar(50) PRIMARY KEY, value varchar(500));
CREATE TABLE cpeEcosystemCache (vendor VARCHAR(255), product VARCHAR(255), ecosystem VARCHAR(255), PRIMARY KEY (vendor, product));
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('apache', 'zookeeper', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('tensorflow', 'tensorflow', 'MULTIPLE');
INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES ('scikit-learn', 'scikit-learn', 'MULTIPLE');

CREATE INDEX idxCwe ON cweEntry(cveid);
CREATE INDEX idxVulnerability ON vulnerability(cve);
CREATE INDEX idxReference ON reference(cveid);
CREATE INDEX idxSoftwareCve ON software(cveid);
CREATE INDEX idxSoftwareCpe ON software(cpeEntryId);

--on mssql we cannot index all columns due to key length issues
CREATE INDEX idxCpeEntry ON cpeEntry(part, vendor, product, version);
--, update_version, edition, lang, sw_edition, target_sw, target_hw, other);


GO

CREATE PROCEDURE save_property (@prop VARCHAR(50), @value VARCHAR(500))
AS
BEGIN
IF EXISTS(SELECT * FROM properties WHERE id=@prop)
    UPDATE properties SET value=@value WHERE id=@prop;
ELSE
    INSERT INTO properties (id, value) VALUES (@prop, @value);
END;

GO

CREATE PROCEDURE merge_ecosystem (@vendor VARCHAR(255), @product VARCHAR(255), @ecosystem varchar(255))
AS
BEGIN
IF EXISTS(SELECT * FROM cpeEcosystemCache WHERE vendor=@vendor AND product=@product)
    UPDATE cpeEcosystemCache SET ecosystem=@ecosystem WHERE vendor=@vendor AND product=@product;
ELSE
    INSERT INTO cpeEcosystemCache (vendor, product, ecosystem) VALUES (@vendor, @product, @ecosystem);
END;

GO

CREATE PROCEDURE update_vulnerability (
    @cveId VARCHAR(20), @description VARCHAR(8000), @v2Severity VARCHAR(20), 
    @v2ExploitabilityScore DECIMAL(3,1), @v2ImpactScore DECIMAL(3,1), @v2AcInsufInfo BIT, 
    @v2ObtainAllPrivilege BIT, @v2ObtainUserPrivilege BIT, @v2ObtainOtherPrivilege BIT, 
    @v2UserInteractionRequired BIT, @v2Score DECIMAL(3,1), @v2AccessVector VARCHAR(20), 
    @v2AccessComplexity VARCHAR(20), @v2Authentication VARCHAR(20), @v2ConfidentialityImpact VARCHAR(20), 
    @v2IntegrityImpact VARCHAR(20), @v2AvailabilityImpact VARCHAR(20), @v2Version VARCHAR(5),
    @v3ExploitabilityScore DECIMAL(3,1), @v3ImpactScore DECIMAL(3,1), @v3AttackVector VARCHAR(20), 
    @v3AttackComplexity VARCHAR(20), @v3PrivilegesRequired VARCHAR(20), @v3UserInteraction VARCHAR(20), 
    @v3Scope VARCHAR(20), @v3ConfidentialityImpact VARCHAR(20), @v3IntegrityImpact VARCHAR(20), 
    @v3AvailabilityImpact VARCHAR(20), @v3BaseScore DECIMAL(3,1), @v3BaseSeverity VARCHAR(20), 
    @v3Version VARCHAR(5)) AS
BEGIN
DECLARE @vulnerabilityId INT;

SELECT @vulnerabilityId=id FROM vulnerability WHERE cve=@cveId;

IF @vulnerabilityId > 0
BEGIN
    DELETE FROM reference WHERE cveid = @vulnerabilityId;
    DELETE FROM software WHERE cveid = @vulnerabilityId;
    DELETE FROM cweEntry WHERE cveid = @vulnerabilityId;
    UPDATE vulnerability SET description=@description,
        v2Severity=@v2Severity, v2ExploitabilityScore=@v2ExploitabilityScore, v2ImpactScore=@v2ImpactScore, 
        v2AcInsufInfo=@v2AcInsufInfo, v2ObtainAllPrivilege=@v2ObtainAllPrivilege,
        v2ObtainUserPrivilege=@v2ObtainUserPrivilege, v2ObtainOtherPrivilege=@v2ObtainOtherPrivilege, 
        v2UserInteractionRequired=@v2UserInteractionRequired, v2Score=@v2Score, v2AccessVector=@v2AccessVector, 
        v2AccessComplexity=@v2AccessComplexity, v2Authentication=@v2Authentication, v2ConfidentialityImpact=@v2ConfidentialityImpact, 
        v2IntegrityImpact=@v2IntegrityImpact, v2AvailabilityImpact=@v2AvailabilityImpact, v2Version=@v2Version, 
        v3ExploitabilityScore=@v3ExploitabilityScore, v3ImpactScore=@v3ImpactScore, v3AttackVector=@v3AttackVector, 
        v3AttackComplexity=@v3AttackComplexity, v3PrivilegesRequired=@v3PrivilegesRequired, v3UserInteraction=@v3UserInteraction, 
        v3Scope=@v3Scope, v3ConfidentialityImpact=@v3ConfidentialityImpact, v3IntegrityImpact=@v3IntegrityImpact, 
        v3AvailabilityImpact=@v3AvailabilityImpact, v3BaseScore=@v3BaseScore, v3BaseSeverity=@v3BaseSeverity, v3Version=@v3Version
    WHERE id=@vulnerabilityId;
END
ELSE
BEGIN
    INSERT INTO vulnerability (cve, description, 
        v2Severity, v2ExploitabilityScore, 
        v2ImpactScore, v2AcInsufInfo, v2ObtainAllPrivilege, 
        v2ObtainUserPrivilege, v2ObtainOtherPrivilege, v2UserInteractionRequired, 
        v2Score, v2AccessVector, v2AccessComplexity, 
        v2Authentication, v2ConfidentialityImpact, v2IntegrityImpact, 
        v2AvailabilityImpact, v2Version, v3ExploitabilityScore, 
        v3ImpactScore, v3AttackVector, v3AttackComplexity, 
        v3PrivilegesRequired, v3UserInteraction, v3Scope, 
        v3ConfidentialityImpact, v3IntegrityImpact, v3AvailabilityImpact, 
        v3BaseScore, v3BaseSeverity, v3Version)
        VALUES (@cveId, @description, 
        @v2Severity, @v2ExploitabilityScore, 
        @v2ImpactScore, @v2AcInsufInfo, @v2ObtainAllPrivilege, 
        @v2ObtainUserPrivilege, @v2ObtainOtherPrivilege, @v2UserInteractionRequired, 
        @v2Score, @v2AccessVector, @v2AccessComplexity, 
        @v2Authentication, @v2ConfidentialityImpact, @v2IntegrityImpact, 
        @v2AvailabilityImpact, @v2Version, @v3ExploitabilityScore, 
        @v3ImpactScore, @v3AttackVector, @v3AttackComplexity, 
        @v3PrivilegesRequired, @v3UserInteraction, @v3Scope, 
        @v3ConfidentialityImpact, @v3IntegrityImpact, @v3AvailabilityImpact, 
        @v3BaseScore, @v3BaseSeverity, @v3Version);
        
        SET @vulnerabilityId = SCOPE_IDENTITY();
END;

SELECT @vulnerabilityId;

END

GO

CREATE PROCEDURE insert_software (
    @vulnerabilityId INT, @part CHAR(1), @vendor VARCHAR(255), @product VARCHAR(255),
    @version VARCHAR(255), @update_version VARCHAR(255), @edition VARCHAR(255), @lang VARCHAR(20),
    @sw_edition VARCHAR(255), @target_sw VARCHAR(255), @target_hw VARCHAR(255), @other VARCHAR(255), 
    @ecosystem VARCHAR(255), @versionEndExcluding VARCHAR(50), @versionEndIncluding VARCHAR(50), 
    @versionStartExcluding VARCHAR(50), @versionStartIncluding VARCHAR(50), @vulnerable BIT) AS
BEGIN
    DECLARE @cpeId INT;
    DECLARE @currentEcosystem VARCHAR(255);
    SET @cpeId=0;
    
    SELECT @cpeId=id, @currentEcosystem=ecosystem 
    FROM cpeEntry WHERE part=@part AND vendor=@vendor AND product=@product
        AND [version]=@version AND update_version=@update_version AND [edition]=@edition 
        AND lang=@lang AND sw_edition=@sw_edition AND target_sw=@target_sw 
        AND target_hw=@target_hw AND other=@other;

    IF @cpeId > 0
    BEGIN
        IF @currentEcosystem IS NULL AND @ecosystem IS NOT NULL
        BEGIN
            UPDATE cpeEntry SET ecosystem=@ecosystem WHERE id=@cpeId;
        END
    END
    ELSE
    BEGIN
        INSERT INTO cpeEntry (part, vendor, product, [version], update_version, 
            [edition], lang, sw_edition, target_sw, target_hw, other, ecosystem) 
        VALUES (@part, @vendor, @product, @version, @update_version, 
                @edition, @lang, @sw_edition, @target_sw, @target_hw, @other, @ecosystem);
        SET @cpeId = SCOPE_IDENTITY();
    END

    INSERT INTO software (cveid, cpeEntryId, versionEndExcluding, versionEndIncluding,
            versionStartExcluding, versionStartIncluding, vulnerable) 
    VALUES (@vulnerabilityId, @cpeId, @versionEndExcluding, @versionEndIncluding,
            @versionStartExcluding, @versionStartIncluding, @vulnerable);
END;


GO

INSERT INTO properties(id,value) VALUES ('version','5.2');

GO
/**
--dcuser with the default password should be given db_datareader
-- a new account used only for updates should be created and granted the following permissions.
CREATE LOGIN dcuser   
    WITH PASSWORD = 'DC-Pass1337!';  
GO
CREATE USER dcuser FOR LOGIN dcuser;  
GO
EXEC sp_addrolemember 'db_datareader', 'dcuser'
EXEC sp_addrolemember 'db_datawriter', 'dcuser'
GO 

GO
GRANT EXECUTE ON save_property TO dcuser; 
GRANT EXECUTE ON merge_ecosystem TO dcuser; 
GRANT EXECUTE ON update_vulnerability TO dcuser; 
GRANT EXECUTE ON insert_software TO dcuser; 
GO
**/
