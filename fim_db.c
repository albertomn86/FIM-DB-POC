#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include "fim_db.h"

static fdb_t fim_db;

static const char *SQL_STMT[] = {
    [FIMDB_STMT_INSERT_DATA] = "INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_INSERT_PATH] = "INSERT INTO entry_path (path, inode_id, mode, last_event, entry_type, scanned, options, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_GET_PATH] = "SELECT entry_path.*, entry_data.* FROM entry_path INNER JOIN entry_data ON path = ? AND entry_data.rowid = entry_path.inode_id",
    [FIMDB_STMT_GET_INODE] = "SELECT entry_path.*, entry_data.* FROM entry_path INNER JOIN entry_data ON inode = ? AND dev = ? AND entry_data.rowid = entry_path.inode_id",
    [FIMDB_STMT_GET_LAST_ROWID] = "SELECT last_insert_rowid()",
    [FIMDB_STMT_GET_ALL_ENTRIES] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_data INNER JOIN entry_path ON inode_id = entry_data.rowid ORDER BY PATH ASC;",
    [FIMDB_STMT_GET_NOT_SCANNED] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_data INNER JOIN entry_path ON inode_id = entry_data.rowid WHERE scanned = 0 ORDER BY PATH ASC;",
    [FIMDB_STMT_SET_ALL_UNSCANNED] = "UPDATE entry_path SET scanned = 0;",
    [FIMDB_STMT_DELETE_UNSCANNED] = "DELETE FROM entry_path WHERE scanned = 0;",
    [FIMDB_STMT_UPDATE_ENTRY_DATA] = "UPDATE entry_data SET size = ?, perm = ?, attributes = ?, uid = ?, gid = ?, user_name = ?, group_name = ?, hash_md5 = ?, hash_sha1 = ?, hash_sha256 = ?, mtime = ? WHERE dev = ? AND inode = ?;",
    [FIMDB_STMT_UPDATE_ENTRY_PATH] = "UPDATE entry_path SET mode = ?, last_event = ?, entry_type = ?, scanned = ?, options = ?, checksum = ? WHERE inode_id = (SELECT rowid FROM entry_data WHERE dev = ? AND inode = ?);",
    [FIMDB_STMT_GET_PATH_COUNT] = "SELECT count(*), inode_id FROM entry_path WHERE path = ?;",
    [FIMDB_STMT_DELETE_DATA_ID] = "DELETE FROM entry_data WHERE rowid = ?;",
    [FIMDB_STMT_GET_DATA_ROW] = "SELECT rowid FROM entry_data WHERE inode = ? AND dev = ?;",
    [FIMDB_STMT_DELETE_DATA_ROW] = "DELETE FROM entry_data WHERE rowid = ?;",
    [FIMDB_STMT_DELETE_PATH_INODE] = "DELETE FROM entry_path WHERE inode_id = ?;",
    [FIMDB_STMT_DELETE_PATH] = "DELETE FROM entry_path WHERE path = ?;",
    [FIMDB_STMT_DISABLE_SCANNED] = "UPDATE entry_data SET scanned = 0;"
};

static fim_entry_data *fim_decode_full_row(sqlite3_stmt *stmt);
static int fim_exec_simple_wquery(const char *query);
static int fim_db_process_get_query(fdb_stmt query_id, const char * start, const char * end, int (*callback)(fim_entry_data *));

int fim_db_clean(void) {
    if(w_is_file(FIM_DB_PATH)) {
        return remove(FIM_DB_PATH);
    }
    return 0;
}


int fim_db_init(void) {
    memset(&fim_db, 0, sizeof(fdb_t));
    fim_db.transaction.interval = COMMIT_INTERVAL;

    if(fim_db_clean() < 0) {
        return DB_ERR;
    }

    if (wdb_create_file(FIM_DB_PATH, schema_fim_sql) < 0) {
        return DB_ERR;
    }

    if (sqlite3_open_v2(FIM_DB_PATH, &fim_db.db, SQLITE_OPEN_READWRITE, NULL)) {
        return DB_ERR;
    }

    if (fim_exec_simple_wquery("BEGIN;") == DB_ERR) {
        return DB_ERR;
    }

    return 0;
}


int fim_db_insert(const char* file_path, fim_entry_data *entry) {
    int retval = DB_ERR;
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_INSERT_DATA);
    if (!stmt) {
        goto end;
    }

    sqlite3_bind_int(stmt, 1, entry->dev);
    sqlite3_bind_int(stmt, 2, entry->inode);
    sqlite3_bind_int(stmt, 3, entry->size);
    sqlite3_bind_text(stmt, 4, entry->perm, -1, NULL);
    sqlite3_bind_text(stmt, 5, entry->attributes, -1, NULL);
    sqlite3_bind_text(stmt, 6, entry->uid, -1, NULL);
    sqlite3_bind_text(stmt, 7, entry->gid, -1, NULL);
    sqlite3_bind_text(stmt, 8, entry->user_name, -1, NULL);
    sqlite3_bind_text(stmt, 9, entry->group_name, -1, NULL);
    sqlite3_bind_text(stmt, 10, entry->hash_md5, -1, NULL);
    sqlite3_bind_text(stmt, 11, entry->hash_sha1, -1, NULL);
    sqlite3_bind_text(stmt, 12, entry->hash_sha256, -1, NULL);
    sqlite3_bind_int(stmt, 13, entry->mtime);


    switch(sqlite3_step(stmt)) {
    case SQLITE_DONE:
        // Get ID
        if (stmt = fim_db_cache(FIMDB_STMT_GET_LAST_ROWID), !stmt) {
            goto end;
        }
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int row_id = sqlite3_column_int(stmt, 0);
            // Insert in inode_path
            if (stmt = fim_db_cache(FIMDB_STMT_INSERT_PATH), !stmt) {
                goto end;
            }
            sqlite3_bind_text(stmt, 1, file_path, -1, NULL);
            sqlite3_bind_int(stmt, 2, row_id);
            sqlite3_bind_int(stmt, 3, entry->mode);
            sqlite3_bind_int(stmt, 4, entry->last_event);
            sqlite3_bind_int(stmt, 5, entry->entry_type);
            sqlite3_bind_int(stmt, 6, entry->scanned);
            sqlite3_bind_int(stmt, 7, entry->options);
            sqlite3_bind_text(stmt, 8, entry->checksum, -1, NULL);

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                goto end;
            }
        }
        break;

    case SQLITE_CONSTRAINT: // File already in entry_data (link)
        // Update entry_data
        if (stmt = fim_db_cache(FIMDB_STMT_UPDATE_ENTRY_DATA), !stmt) {
            goto end;
        }
        sqlite3_bind_int(stmt, 1, entry->size);
        sqlite3_bind_text(stmt, 2, entry->perm, -1, NULL);
        sqlite3_bind_text(stmt, 3, entry->attributes, -1, NULL);
        sqlite3_bind_text(stmt, 4, entry->uid, -1, NULL);
        sqlite3_bind_text(stmt, 5, entry->gid, -1, NULL);
        sqlite3_bind_text(stmt, 6, entry->user_name, -1, NULL);
        sqlite3_bind_text(stmt, 7, entry->group_name, -1, NULL);
        sqlite3_bind_text(stmt, 8, entry->hash_md5, -1, NULL);
        sqlite3_bind_text(stmt, 9, entry->hash_sha1, -1, NULL);
        sqlite3_bind_text(stmt, 10, entry->hash_sha256, -1, NULL);
        sqlite3_bind_int(stmt, 11, entry->mtime);
        sqlite3_bind_int(stmt, 12, entry->dev);
        sqlite3_bind_int(stmt, 13, entry->inode);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            merror("SQL ERROR: %s", sqlite3_errmsg(fim_db.db));
            goto end;
        }

        // Add to entry_path
        // Get ID
        sqlite3_prepare_v2(fim_db.db, SQL_STMT[FIMDB_STMT_GET_DATA_ROW], -1, &stmt, 0);
        sqlite3_bind_int(stmt, 1, entry->dev);
        sqlite3_bind_int(stmt, 2, entry->inode);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int row_id = sqlite3_column_int(stmt, 0);
            // Insert in inode_path
            sqlite3_prepare_v2(fim_db.db, SQL_STMT[FIMDB_STMT_INSERT_PATH], -1, &stmt, 0);

            sqlite3_bind_text(stmt, 1, file_path, -1, NULL);
            sqlite3_bind_int(stmt, 2, row_id);
            sqlite3_bind_int(stmt, 3, entry->mode);
            sqlite3_bind_int(stmt, 4, entry->last_event);
            sqlite3_bind_int(stmt, 5, entry->entry_type);
            sqlite3_bind_int(stmt, 6, entry->scanned);
            sqlite3_bind_int(stmt, 7, entry->options);
            sqlite3_bind_text(stmt, 8, entry->checksum, -1, NULL);

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                merror("SQL ERROR: %s", sqlite3_errmsg(fim_db.db));
                goto end;
            }
        }
    }

    retval = 0;
end:
    fim_check_transaction();
    return retval;
}


int fim_db_remove_path(const char * file_path) {
    int retval = DB_ERR;
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_GET_PATH_COUNT);
    if (!stmt) {
        goto end;
    }

    sqlite3_bind_text(stmt, 1, file_path, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int rows = sqlite3_column_int(stmt, 0);
        switch (rows) {
        case 0:
            // No entries with this path.
            break;
        case 1:
            // The inode has only one entry, delete the entry data.
            if (stmt = fim_db_cache(FIMDB_STMT_DELETE_DATA_ID), !stmt) {
                goto end;
            }
            sqlite3_bind_text(stmt, 1, sqlite3_column_text(stmt, 1), -1, NULL);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                goto end;
            }
            // Fallthrough
        default:
            // The inode has more entries, delete only this path.
            if (stmt = fim_db_cache(FIMDB_STMT_DELETE_PATH), !stmt) {
                goto end;
            }
            sqlite3_bind_text(stmt, 1, file_path, -1, NULL);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                goto end;
            }
            break;
        }
    }

    retval = 0;
end:
    fim_check_transaction();
    return retval;
}


int fim_db_remove_inode(const unsigned long int inode, const unsigned long int dev) {
    int retval = DB_ERR;
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_GET_DATA_ROW);
    if (!stmt) {
        goto end;
    }

    sqlite3_bind_int(stmt, 1, inode);
    sqlite3_bind_int(stmt, 2, dev);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int row_id = sqlite3_column_int(stmt, 0);
        // Delete the entry data.
        if (stmt = fim_db_cache(FIMDB_STMT_DELETE_DATA_ROW), !stmt) {
            goto end;
        }
        sqlite3_bind_int(stmt, 1, row_id);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            goto end;
        }

        // Delete all paths with this inode.
        if (stmt = fim_db_cache(FIMDB_STMT_DELETE_PATH_INODE), !stmt) {
            goto end;
        }
        sqlite3_bind_int(stmt, 1, row_id);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            goto end;
        }
    }

    retval = 0;
end:
    fim_check_transaction();
    return retval;
}


fim_entry_data * fim_db_get_inode(const unsigned long int inode, const unsigned long int dev) {
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_GET_INODE);
    fim_entry_data *entry = NULL;
    if (!stmt) {
        goto end;
    }

    sqlite3_bind_int(stmt, 1, inode);
    sqlite3_bind_int(stmt, 2, dev);

    int result = 0;
    unsigned int size = 0;

    while (result = sqlite3_step(stmt), result == SQLITE_ROW) {

        entry = realloc(entry, (size + 2) * sizeof(fim_entry_data));
        memset(&entry[size], 0, 2 * sizeof(fim_entry_data));

        w_strdup((char *)sqlite3_column_text(stmt, 0), entry[size].path);
        entry[size].mode = (unsigned int)sqlite3_column_int(stmt, 2);
        entry[size].last_event = (time_t)sqlite3_column_int(stmt, 3);
        entry[size].entry_type = sqlite3_column_int(stmt, 4);
        entry[size].scanned = (time_t)sqlite3_column_int(stmt, 5);
        entry[size].options = (time_t)sqlite3_column_int(stmt, 6);
        w_strdup((char *)sqlite3_column_text(stmt, 7), entry[size].checksum);
        entry[size].dev = (unsigned long int)sqlite3_column_int(stmt, 8);
        entry[size].inode = (unsigned long int)sqlite3_column_int(stmt, 9);
        entry[size].size = (unsigned int)sqlite3_column_int(stmt, 10);
        w_strdup((char *)sqlite3_column_text(stmt, 11), entry[size].perm);
        w_strdup((char *)sqlite3_column_text(stmt, 12), entry[size].attributes);
        w_strdup((char *)sqlite3_column_text(stmt, 13), entry[size].uid);
        w_strdup((char *)sqlite3_column_text(stmt, 14), entry[size].gid);
        w_strdup((char *)sqlite3_column_text(stmt, 15), entry[size].user_name);
        w_strdup((char *)sqlite3_column_text(stmt, 16), entry[size].group_name);
        w_strdup((char *)sqlite3_column_text(stmt, 17), entry[size].hash_md5);
        w_strdup((char *)sqlite3_column_text(stmt, 18), entry[size].hash_sha1);
        w_strdup((char *)sqlite3_column_text(stmt, 19), entry[size].hash_sha256);
        entry[size].mtime = (unsigned int)sqlite3_column_int(stmt, 10);

        size++;
    }

end:
    fim_check_transaction();
    return entry;
}


fim_entry_data * fim_db_get_path(const char * file_path) {
    fim_entry_data *entry = NULL;
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_GET_PATH);
    if (!stmt) {
        goto end;
    }
    sqlite3_bind_text(stmt, 1, file_path, -1, NULL);

    int result = 0;
    unsigned int size = 0;

    while (result = sqlite3_step(stmt), result == SQLITE_ROW) {

        entry = realloc(entry, (size + 2) * sizeof(fim_entry_data));
        memset(&entry[size], 0, 2 * sizeof(fim_entry_data));

        w_strdup((char *)sqlite3_column_text(stmt, 0), entry[size].path);
        entry[size].mode = (unsigned int)sqlite3_column_int(stmt, 2);
        entry[size].last_event = (time_t)sqlite3_column_int(stmt, 3);
        entry[size].entry_type = sqlite3_column_int(stmt, 4);
        entry[size].scanned = (time_t)sqlite3_column_int(stmt, 5);
        entry[size].options = (time_t)sqlite3_column_int(stmt, 6);
        w_strdup((char *)sqlite3_column_text(stmt, 7), entry[size].checksum);
        entry[size].dev = (unsigned long int)sqlite3_column_int(stmt, 8);
        entry[size].inode = (unsigned long int)sqlite3_column_int(stmt, 9);
        entry[size].size = (unsigned int)sqlite3_column_int(stmt, 10);
        w_strdup((char *)sqlite3_column_text(stmt, 11), entry[size].perm);
        w_strdup((char *)sqlite3_column_text(stmt, 12), entry[size].attributes);
        w_strdup((char *)sqlite3_column_text(stmt, 13), entry[size].uid);
        w_strdup((char *)sqlite3_column_text(stmt, 14), entry[size].gid);
        w_strdup((char *)sqlite3_column_text(stmt, 15), entry[size].user_name);
        w_strdup((char *)sqlite3_column_text(stmt, 16), entry[size].group_name);
        w_strdup((char *)sqlite3_column_text(stmt, 17), entry[size].hash_md5);
        w_strdup((char *)sqlite3_column_text(stmt, 18), entry[size].hash_sha1);
        w_strdup((char *)sqlite3_column_text(stmt, 19), entry[size].hash_sha256);
        entry[size].mtime = (unsigned int)sqlite3_column_int(stmt, 10);

        size++;
    }

end:
    fim_check_transaction();
    return entry;
}


int fim_db_set_not_scanned(void) {
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_DISABLE_SCANNED);
    if (!stmt) {
        fim_check_transaction();
        return DB_ERR;
    }

    int ret = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        ret = 0;
    }

    fim_check_transaction();
    return ret;
}


int fim_db_get_all(int (*callback)(fim_entry_data *)) {
    return fim_db_process_get_query(FIMDB_STMT_GET_ALL_ENTRIES, NULL, NULL, callback);
}


int fim_db_get_range(const char * start, const char * end, int (*callback)(fim_entry_data *)) {
    return fim_db_process_get_query(FIMDB_STMT_GET_ALL_ENTRIES, start, end, callback);
}


int fim_db_get_not_scanned(int (*callback)(fim_entry_data *)) {
    return fim_db_process_get_query(FIMDB_STMT_GET_NOT_SCANNED, NULL, NULL, callback);
}


fim_entry_data *fim_decode_full_row(sqlite3_stmt *stmt) {
    fim_entry_data *entry = calloc(1, sizeof(fim_entry_data));

    w_strdup((char *)sqlite3_column_text(stmt, 0), entry->path);
    entry->inode = (unsigned int)sqlite3_column_int(stmt, 1);
    entry->mode = (unsigned int)sqlite3_column_int(stmt, 2);
    entry->last_event = (unsigned int)sqlite3_column_int(stmt, 3);
    entry->entry_type = (unsigned int)sqlite3_column_int(stmt, 4);
    entry->scanned = (unsigned int)sqlite3_column_int(stmt, 5);
    entry->options = (unsigned int)sqlite3_column_int(stmt, 6);
    entry->dev = (unsigned int)sqlite3_column_int(stmt, 7);
    entry->inode = (unsigned int)sqlite3_column_int(stmt, 8);
    entry->size = (unsigned int)sqlite3_column_int(stmt, 9);
    w_strdup((char *)sqlite3_column_text(stmt, 10), entry->perm);
    w_strdup((char *)sqlite3_column_text(stmt, 11), entry->attributes);
    w_strdup((char *)sqlite3_column_text(stmt, 12), entry->uid);
    w_strdup((char *)sqlite3_column_text(stmt, 13), entry->gid);
    w_strdup((char *)sqlite3_column_text(stmt, 14), entry->user_name);
    w_strdup((char *)sqlite3_column_text(stmt, 15), entry->group_name);
    w_strdup((char *)sqlite3_column_text(stmt, 16), entry->hash_md5);
    w_strdup((char *)sqlite3_column_text(stmt, 17), entry->hash_sha1);
    w_strdup((char *)sqlite3_column_text(stmt, 18), entry->hash_sha256);
    entry->mtime = (unsigned int)sqlite3_column_int(stmt, 18);

    fim_check_transaction();
    return entry;
}


int fim_db_set_all_unscanned(void) {
    int retval = fim_exec_simple_wquery(SQL_STMT[FIMDB_STMT_SET_ALL_UNSCANNED]);
    fim_check_transaction();
    return retval;
}


int fim_db_delete_unscanned(void) {
    int retval = fim_exec_simple_wquery(SQL_STMT[FIMDB_STMT_DELETE_UNSCANNED]);
    fim_check_transaction();
    return retval;
}


int fim_exec_simple_wquery(const char *query) {
    char *error = NULL;
    sqlite3_exec(fim_db.db, query, NULL, NULL, &error);
    if (error) {
        merror("SQL ERROR: %s", error);
        sqlite3_free(error);
        return DB_ERR;
    }
    return 0;
}


int fim_db_update(const unsigned long int inode, const unsigned long int dev, fim_entry_data *entry) {
    int retval = DB_ERR;
    // Update entry_data
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_UPDATE_ENTRY_DATA);
    if (!stmt) {
        goto end;
    }

    sqlite3_bind_int(stmt, 1, entry->size);
    sqlite3_bind_text(stmt, 2, entry->perm, -1, NULL);
    sqlite3_bind_text(stmt, 3, entry->attributes, -1, NULL);
    sqlite3_bind_text(stmt, 4, entry->uid, -1, NULL);
    sqlite3_bind_text(stmt, 5, entry->gid, -1, NULL);
    sqlite3_bind_text(stmt, 6, entry->user_name, -1, NULL);
    sqlite3_bind_text(stmt, 7, entry->group_name, -1, NULL);
    sqlite3_bind_text(stmt, 8, entry->hash_md5, -1, NULL);
    sqlite3_bind_text(stmt, 9, entry->hash_sha1, -1, NULL);
    sqlite3_bind_text(stmt, 10, entry->hash_sha256, -1, NULL);
    sqlite3_bind_int(stmt, 11, entry->mtime);
    sqlite3_bind_int(stmt, 12, entry->dev);
    sqlite3_bind_int(stmt, 13, entry->inode);

    int result;
    if (result = sqlite3_step(stmt), result != SQLITE_DONE) {
        merror("SQL ERROR: %s", sqlite3_errmsg(fim_db.db));
        goto end;
    }

    // Update entry_path
    if (stmt = fim_db_cache(FIMDB_STMT_UPDATE_ENTRY_PATH), !stmt) {
        goto end;
    }

    sqlite3_bind_int(stmt, 1, entry->mode);
    sqlite3_bind_int(stmt, 2, entry->last_event);
    sqlite3_bind_int(stmt, 3, entry->entry_type);
    sqlite3_bind_int(stmt, 4, entry->scanned);
    sqlite3_bind_int(stmt, 5, entry->options);
    sqlite3_bind_text(stmt, 6, entry->checksum, -1, NULL);
    sqlite3_bind_int(stmt, 7, entry->dev);
    sqlite3_bind_int(stmt, 8, entry->inode);
    if (result = sqlite3_step(stmt), result != SQLITE_DONE) {
        merror("SQL ERROR: %s", sqlite3_errmsg(fim_db.db));
        goto end;
    }

    retval = 0;
end:
    fim_check_transaction();
    return retval;
}


int fim_db_process_get_query(fdb_stmt query_id, const char * start, const char * end, int (*callback)(fim_entry_data *)) {
    sqlite3_stmt *stmt = fim_db_cache(query_id);
    if (!stmt) {
        fim_check_transaction();
        return DB_ERR;
    }

    int result;
    char init_found = 0;
    while (result = sqlite3_step(stmt), result == SQLITE_ROW) {
        char *path = (char *)sqlite3_column_text(stmt, 0);
        if (!path) {
            continue;
        }

        if (!init_found && start && strcmp(start, path)) {
            continue;
        }
        init_found = 1;

        fim_entry_data *entry = fim_decode_full_row(stmt);
        callback((void *) entry);

        if (end && !strcmp(end, path)) {
            result = SQLITE_DONE;
            break;
        }
    }

    fim_check_transaction();
    return result != SQLITE_DONE ? DB_ERR : 0;
}


void fim_check_transaction() {
    time_t now = time(NULL);
    if (fim_db.transaction.last_commit + fim_db.transaction.interval <= now) {
        // If the completion of the transaction fails, we do not update the timestamp
        if (fim_exec_simple_wquery("END;") != DB_ERR) {
            mdebug1("Database transaction completed.");
            fim_db.transaction.last_commit = now;
            while (fim_exec_simple_wquery("BEGIN;") == DB_ERR);
        }
    }
}


sqlite3_stmt *fim_db_cache(fdb_stmt index) {
    sqlite3_stmt *stmt = NULL;

    if (index >= WDB_STMT_SIZE) {
        merror("Error in fim_db_cache(): Invalid index: %d.", (int) index);
    } else if (!fim_db.stmt[index]) {
        if (sqlite3_prepare_v2(fim_db.db, SQL_STMT[index], -1, &fim_db.stmt[index], NULL) != SQLITE_OK) {
            merror("Error in fim_db_cache(): %s", sqlite3_errmsg(fim_db.db));
        } else {
            stmt = fim_db.stmt[index];
        }
    } else if (sqlite3_reset(fim_db.stmt[index]) != SQLITE_OK || sqlite3_clear_bindings(fim_db.stmt[index]) != SQLITE_OK) {
        wdb_finalize(fim_db.stmt[index]);

        if (sqlite3_prepare_v2(fim_db.db, SQL_STMT[index], -1, &fim_db.stmt[index], NULL) != SQLITE_OK) {
            merror("Error in fim_db_cache(): %s", sqlite3_errmsg(fim_db.db));
        }
    }  else {
        stmt = fim_db.stmt[index];
    }

    return stmt;
}
