
DROP PROCEDURE IF EXISTS save_property;

DELIMITER //
CREATE PROCEDURE save_property
(IN prop varchar(50), IN val varchar(500))
BEGIN
INSERT INTO properties (`id`, `value`) VALUES (prop, val)
	ON DUPLICATE KEY UPDATE `value`=val;
END //
DELIMITER ;

GRANT EXECUTE ON PROCEDURE dependencycheck.save_property TO 'dcuser';

UPDATE properties SET value='3.0' WHERE ID='version';
