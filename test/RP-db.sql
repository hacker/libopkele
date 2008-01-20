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
 n_op text NOT NULL,
 n_once text NOT NULL,
 PRIMARY KEY (n_op,n_once)
);

CREATE TABLE ht_sessions (
 hts_id text NOT NULL PRIMARY KEY
);

CREATE TABLE auth_sessions (
 as_id integer PRIMARY KEY AUTOINCREMENT,
 hts_id text NOT NULL REFERENCES ht_sessions(hts_id),
 as_normalized_id text,
 UNIQUE (hts_id,as_id)
);

CREATE TABLE endpoints_queue (
 as_id integer NOT NULL REFERENCES auth_sessions (as_id),
 eq_ctime integer NOT NULL,
 eq_ordinal integer NOT NULL,
 eq_uri text,
 eq_claimed_id text,
 eq_local_id text
);
