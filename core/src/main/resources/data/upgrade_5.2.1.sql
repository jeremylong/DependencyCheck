UPDATE cpeEcosystemCache set ecosystem='MULTIPLE' where vendor = 'apache' and product = 'hadoop';

UPDATE Properties SET `value`='5.2.2' WHERE ID='version';