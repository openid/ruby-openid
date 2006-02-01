CREATE TABLE openid_associations (
  "id" serial primary key,
  "server_url" bytea,
  "handle" character varying(255),
  "secret" bytea,
  "issued" integer,
  "lifetime" integer,
  "assoc_type" character varying(255)
);

CREATE TABLE openid_nonces (
  "id" serial primary key,
  "nonce" character varying(255),
  "created" integer
);

CREATE TABLE openid_settings (
  "id" serial primary key,
  "setting" character varying(255),
  "value" bytea
);
