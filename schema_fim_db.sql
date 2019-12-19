/*
 * SQL Schema for FIM database
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE IF NOT EXISTS entry_path (
    path TEXT NOT NULL,
    inode_id INTEGER,
    mode INTEGER,
    last_event INTEGER,
    entry_type INTEGER,
    scanned INTEGER,
    options INTEGER,
    checksum TEXT NOT NULL,
    PRIMARY KEY(path)
);

CREATE UNIQUE INDEX path_index ON entry_path(path, inode_id, scanned);

CREATE TABLE IF NOT EXISTS entry_data (
    dev INTEGER,
    inode INTEGER,
    size INTEGER,
    perm TEXT,
    attributes TEXT,
    uid INTEGER,
    gid INTEGER,
    user_name TEXT,
    group_name TEXT,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    mtime INTEGER
);

CREATE UNIQUE INDEX data_index ON entry_data(dev, inode);

PRAGMA journal_mode=WAL;
