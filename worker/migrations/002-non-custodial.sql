-- Drops the custodial account key columns. Run before re-applying schema.sql.
DROP TABLE IF EXISTS calls;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS pairings;
DROP TABLE IF EXISTS accounts;
