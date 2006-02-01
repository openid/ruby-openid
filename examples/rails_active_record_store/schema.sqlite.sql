CREATE TABLE openid_associations (
  "id" INTEGER PRIMARY KEY NOT NULL,
  "server_url" blob,
  "handle" varchar(255),
  "secret" blob,
  "issued" integer,
  "lifetime" integer,
  "assoc_type" varchar(255)
);

CREATE TABLE openid_nonces (
  "id" INTEGER PRIMARY KEY NOT NULL,
  "nonce" varchar(255),
  "created" integer
);

CREATE TABLE openid_settings (
  "id" INTEGER PRIMARY KEY NOT NULL,
  "setting" varchar(255),
  "value" blob
);
