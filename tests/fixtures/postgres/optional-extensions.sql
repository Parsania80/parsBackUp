-- Run only when the target extension package is available.
CREATE EXTENSION IF NOT EXISTS hstore;
CREATE TABLE app.extension_values (id integer PRIMARY KEY, attributes hstore);
INSERT INTO app.extension_values VALUES (1, 'color=>blue');
