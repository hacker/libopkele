CREATE TABLE assoc (
 a_op text,
 a_handle text NOT NULL,
 a_type text DEFAULT 'HMAC-SHA1',
 a_ctime text NOT NULL,
 a_etime text NOT NULL,
 a_secret text NOT NULL,
 a_stateless integer NOT NULL DEFAULT 0,
 a_itime integer,
 UNIQUE(a_op,a_handle)
);

CREATE TABLE nonces (
 n_once text NOT NULL PRIMARY KEY,
 n_itime integer
);

CREATE TABLE setup (
 s_password text
);

CREATE TABLE ht_sessions (
 hts_id text NOT NULL PRIMARY KEY,
 authorized integer NOT NULL DEFAULT 0
);
