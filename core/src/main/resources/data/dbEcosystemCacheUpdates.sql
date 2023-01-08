UPDATE cpeEcosystemCache set ecosystem='MULTIPLE' where vendor = 'apache' and product = 'hadoop' and ecosystem != 'MULTIPLE';
UPDATE cpeEcosystemCache set ecosystem='MULTIPLE' where vendor = 'apache' and product = 'ranger' and ecosystem != 'MULTIPLE';
