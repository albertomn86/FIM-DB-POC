#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include "fim_db.h"

static pthread_mutex_t fim_db_mutex;

static sqlite3 *db;

#define INSERT_DATA "INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) \
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
#define INSERT_PATH "INSERT INTO entry_path (path, inode_id, mode, last_event, entry_type, scanned, options, checksum) \
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);"
#define GET_PATH    "SELECT dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime, path, path, inode_id, mode, last_event, entry_type, scanned, options, checksum \
                    FROM inode_data INNER JOIN entry_path ON entry_path.inode_id = entry_data.rowid AND entry_path.path = ?"
#define LAST_ROWID "SELECT last_insert_rowid()"
#define GET_ALL_ENTRIES    "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, dev, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_data INNER JOIN entry_path ON inode_id = inode ORDER BY PATH ASC;"

static fim_entry_data *fim_decode_full_row(sqlite3_stmt *stmt);

int fim_db_clean(void) {
    if(w_is_file(FIM_DB_PATH)) {
        return remove(FIM_DB_PATH);
    }
    return 0;
}


int fim_db_init(void) {
    /* ~~~~~~~~~ COMENTADO HASTA QUE TENGAMOS LA FUNCIÓN DE INSERCIÓN LISTA
    if(fim_db_clean() < 0) {
        return DB_ERR;
    }
    */

    if (wdb_create_file(FIM_DB_PATH, schema_fim_sql) < 0) {
        return DB_ERR;
    }

    if (sqlite3_open_v2(FIM_DB_PATH, &db, SQLITE_OPEN_READWRITE, NULL)) { // ~~~~~~~~~~ FOR TESTING PURPOSES
        return DB_ERR;
    }

    return 0;
}


int fim_db_insert(const char* file_path, fim_entry_data *entry) {

    sqlite3_stmt *stmt = NULL;

    sqlite3_prepare_v2(db, INSERT_DATA, -1, &stmt, NULL);

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

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        // Get ID
        sqlite3_prepare_v2(db, LAST_ROWID, -1, &stmt, 0);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int row_id = sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);
            // Insert in inode_path
            sqlite3_prepare_v2(db, INSERT_PATH, -1, &stmt, 0);

            sqlite3_bind_text(stmt, 1, file_path, -1, NULL);
            sqlite3_bind_int(stmt, 2, row_id);
            sqlite3_bind_int(stmt, 3, entry->mode);
            sqlite3_bind_int(stmt, 4, entry->last_event);
            sqlite3_bind_int(stmt, 5, entry->entry_type);
            sqlite3_bind_int(stmt, 6, entry->scanned);
            sqlite3_bind_int(stmt, 7, entry->options);
            sqlite3_bind_text(stmt, 8, entry->checksum, -1, NULL);

            if (sqlite3_step(stmt) == SQLITE_DONE) {
                sqlite3_finalize(stmt);
                return 0;
            }
        }
    }
    sqlite3_finalize(stmt);
    return -1;
}


int fim_db_remove_path(const char * file_path) {

    sqlite3_stmt *stmt = NULL;

    sqlite3_prepare_v2(db, "SELECT count(*), inode_id FROM entry_path WHERE path = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, file_path, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int rows = sqlite3_column_int(stmt, 0);
        switch (rows) {
        case 0:
            // No entries with this path.
            goto exit_err;
        case 1:
            // The inode has only one entry, delete the entry data.
            sqlite3_finalize(stmt);
            sqlite3_prepare_v2(db, "DELETE FROM entry_data WHERE rowid = ?", -1, &stmt, NULL);
            sqlite3_bind_text(stmt, 1, sqlite3_column_text(stmt, 1), -1, NULL);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                goto exit_err;
            }
            // Fallthrough
        default:
            // The inode has more entries, delete only this path.
            sqlite3_finalize(stmt);
            sqlite3_prepare_v2(db, "DELETE FROM entry_path WHERE path = ?", -1, &stmt, NULL);
            sqlite3_bind_text(stmt, 1, file_path, -1, NULL);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                goto exit_err;
            }
            break;
        }
    }

exit_err:
    sqlite3_finalize(stmt);
    return -1;
}


int fim_db_remove_inode(const unsigned long int inode, const unsigned long int dev) {

    sqlite3_stmt *stmt = NULL;

    sqlite3_prepare_v2(db, "SELECT rowid FROM entry_data WHERE inode = ? AND dev = ?", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, inode);
    sqlite3_bind_int(stmt, 2, dev);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int row_id = sqlite3_column_int(stmt, 0);
        // Delete the entry data.
        sqlite3_finalize(stmt);
        sqlite3_prepare_v2(db, "DELETE FROM entry_data WHERE rowid = ?", -1, &stmt, NULL);
        sqlite3_bind_int(stmt, 1, row_id);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            goto exit_err;
        }

        // Delete all paths with this inode.
        sqlite3_finalize(stmt);
        sqlite3_prepare_v2(db, "DELETE FROM entry_path WHERE inode_id = ?", -1, &stmt, NULL);
        sqlite3_bind_int(stmt, 1, row_id);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            goto exit_err;
        }

        sqlite3_finalize(stmt);
        return 0;
    }

exit_err:
    sqlite3_finalize(stmt);
    return -1;
}


fim_entry_data * fim_db_get_inode(const unsigned long int inode, const unsigned long int dev) {

    sqlite3_stmt *stmt = NULL;

    sqlite3_prepare_v2(db, "SELECT * FROM entry_data WHERE inode = ?", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, inode);

    if (sqlite3_step(stmt) == SQLITE_ROW) { // Puede devolver varios!!

        fim_entry_data *entry = calloc(1, sizeof(fim_entry_data));

        entry->size = (unsigned int)sqlite3_column_int(stmt, 1);
        entry->perm = (char *)sqlite3_column_text(stmt, 2);
        entry->attributes = (char *)sqlite3_column_text(stmt, 3);
        entry->uid = (char *)sqlite3_column_text(stmt, 4);
        entry->gid = (char *)sqlite3_column_text(stmt, 5);
        entry->user_name = (char *)sqlite3_column_text(stmt, 6);
        entry->group_name = (char *)sqlite3_column_text(stmt, 7);
        entry->mtime = (unsigned int)sqlite3_column_int(stmt, 8);
        entry->hash_md5 = (char *)sqlite3_column_text(stmt, 9);
        entry->hash_sha1 = (char *)sqlite3_column_text(stmt, 10);
        entry->hash_sha256 = (char *)sqlite3_column_text(stmt, 11);
        entry->mode = (unsigned int)sqlite3_column_int(stmt, 12);
        entry->last_event = (time_t)sqlite3_column_int(stmt, 13);
        entry->entry_type = sqlite3_column_int(stmt, 14);
        entry->scanned = (time_t)sqlite3_column_int(stmt, 15);
        entry->options = (time_t)sqlite3_column_int(stmt, 16);
        entry->checksum = (char *)sqlite3_column_text(stmt, 17);

        sqlite3_finalize(stmt);
        return entry;
    }
    sqlite3_finalize(stmt);
    return NULL;
}


fim_entry_data * fim_db_get_path(const char * file_path) {

    sqlite3_stmt *stmt = NULL;

    sqlite3_prepare_v2(db, GET_PATH, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, file_path, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_ROW) {

        fim_entry_data *entry = calloc(1, sizeof(fim_entry_data));

        entry->size = (unsigned int)sqlite3_column_int(stmt, 1);
        w_strdup((char *)sqlite3_column_text(stmt, 2), entry->perm);
        w_strdup((char *)sqlite3_column_text(stmt, 3), entry->attributes);
        w_strdup((char *)sqlite3_column_text(stmt, 4), entry->uid);
        w_strdup((char *)sqlite3_column_text(stmt, 5), entry->gid);
        w_strdup((char *)sqlite3_column_text(stmt, 6), entry->user_name);
        w_strdup((char *)sqlite3_column_text(stmt, 7), entry->group_name);
        entry->mtime = (unsigned int)sqlite3_column_int(stmt, 8);
        w_strdup((char *)sqlite3_column_text(stmt, 9), entry->hash_md5);
        w_strdup((char *)sqlite3_column_text(stmt, 10), entry->hash_sha1);
        w_strdup((char *)sqlite3_column_text(stmt, 11), entry->hash_sha256);
        entry->mode = (unsigned int)sqlite3_column_int(stmt, 12);
        entry->last_event = (time_t)sqlite3_column_int(stmt, 13);
        entry->entry_type = sqlite3_column_int(stmt, 14);
        entry->scanned = (time_t)sqlite3_column_int(stmt, 15);
        entry->options = (time_t)sqlite3_column_int(stmt, 16);
        w_strdup((char *)sqlite3_column_text(stmt, 17), entry->checksum);

        sqlite3_finalize(stmt);
        return entry;
    }
    sqlite3_finalize(stmt);
    return NULL;
}


int fim_db_set_not_scanned(void) {

    sqlite3_stmt *stmt = NULL;

    sqlite3_prepare_v2(db, "UPDATE entry_data SET scanned = 0", -1, &stmt, NULL);

    int ret = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        ret = 0;
    }

    sqlite3_finalize(stmt);
    return ret;
}

int fim_db_get_all(int (*callback)(fim_entry_data *)) {
    return fim_db_get_range(NULL, NULL, callback);
}

int fim_db_get_range(const char * start, const char * end, int (*callback)(fim_entry_data *)) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (sqlite3_prepare_v2(db, GET_ALL_ENTRIES, -1, &stmt, NULL)  != SQLITE_OK) {
        merror("SQL ERROR: %s", sqlite3_errmsg(db));
        return -1;
    }

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
            break;;
        }
    }

    sqlite3_finalize(stmt);
    return result != SQLITE_DONE ? DB_ERR : 0;
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
    entry->size = (unsigned int)sqlite3_column_int(stmt, 8);
    w_strdup((char *)sqlite3_column_text(stmt, 9), entry->perm);
    w_strdup((char *)sqlite3_column_text(stmt, 10), entry->attributes);
    w_strdup((char *)sqlite3_column_text(stmt, 11), entry->uid);
    w_strdup((char *)sqlite3_column_text(stmt, 12), entry->gid);
    w_strdup((char *)sqlite3_column_text(stmt, 13), entry->user_name);
    w_strdup((char *)sqlite3_column_text(stmt, 14), entry->group_name);
    w_strdup((char *)sqlite3_column_text(stmt, 15), entry->hash_md5);
    w_strdup((char *)sqlite3_column_text(stmt, 16), entry->hash_sha1);
    w_strdup((char *)sqlite3_column_text(stmt, 17), entry->hash_sha256);
    entry->mtime = (unsigned int)sqlite3_column_int(stmt, 18);

    return entry;
}
