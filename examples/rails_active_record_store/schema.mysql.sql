CREATE TABLE openid_associations (
  `id` int(11) DEFAULT NULL auto_increment PRIMARY KEY,
  `server_url` blob,
  `handle` varchar(255),
  `secret` blob,
  `issued` int(11),
  `lifetime` int(11),
  `assoc_type` varchar(255)
) ENGINE=InnoDB;

CREATE TABLE openid_nonces (
  `id` int(11) DEFAULT NULL auto_increment PRIMARY KEY,
  `nonce` varchar(255),
  `created` int(11)
) ENGINE=InnoDB;

CREATE TABLE openid_settings (
  `id` int(11) DEFAULT NULL auto_increment PRIMARY KEY,
  `setting` varchar(255),
  `value` blob
) ENGINE=InnoDB;

