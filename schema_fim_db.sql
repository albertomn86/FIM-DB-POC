/*
 * SQL Schema for FIM database
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE inode_path (
    path TEXT PRIMARY KEY,
    inode_id INTEGER,
    mode INTEGER,
    last_event INTEGER,
    entry_type INTEGER,
    scanned INTEGER,
    options INTEGER,
    checksum TEXT
);

CREATE TABLE inode_data (
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
    mtime INTEGER,
    PRIMARY KEY(dev, inode)
);

PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;
