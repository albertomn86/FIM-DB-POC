#include <pthread.h>
#include <sqlite3.h>
#include "fim_db.h"
#include "dependencies.h"

static pthread_mutex_t fim_db_mutex;
static sqlite3 *db;

#define INSERT_DATA "INSERT INTO inode_data (inode_id, size, perm, attributes, uid, gid, user_name, group_name, mtime, hash_md5, hash_sha1, hash_sha256, mode, last_event, entry_type, scanned, options, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
#define INSERT_PATH "INSERT INTO inode_path (path, inode) VALUES (?, ?);"
#define LAST_ROWID "SELECT last_insert_rowid()"



int fim_db_clean(void) {
    if(w_is_file(FIM_DB_PATH)) {
        return remove(FIM_DB_PATH);
    }
    return 0;
}


int fim_db_init(void) {
    if(fim_db_clean() < 0) {
        return DB_ERR;
    }

    if (wdb_create_file(FIM_DB_PATH, schema_fim_sql) < 0) {
        return DB_ERR;
    }
}


int fim_db_insert(const char* file_path, fim_entry_data *entry) {

    sqlite3_stmt *stmt = NULL;

    sqlite3_prepare_v2(db, INSERT_DATA, -1, &stmt, NULL);

    char dev_inode[128] = {0};
    snprintf(dev_inode, 127, "%ul:%ul", entry->dev, entry->inode);

    sqlite3_bind_text(stmt, 1, dev_inode, -1, NULL);
    sqlite3_bind_int(stmt, 2, entry->size);
    sqlite3_bind_text(stmt, 3, entry->perm, -1, NULL);
    sqlite3_bind_text(stmt, 4, entry->attributes, -1, NULL);
    sqlite3_bind_text(stmt, 5, entry->uid, -1, NULL);
    sqlite3_bind_text(stmt, 6, entry->gid, -1, NULL);
    sqlite3_bind_text(stmt, 7, entry->user_name, -1, NULL);
    sqlite3_bind_text(stmt, 8, entry->group_name, -1, NULL);
    sqlite3_bind_int(stmt, 9, entry->mtime);
    sqlite3_bind_text(stmt, 10, entry->hash_md5, -1, NULL);
    sqlite3_bind_text(stmt, 11, entry->hash_sha1, -1, NULL);
    sqlite3_bind_text(stmt, 12, entry->hash_sha256, -1, NULL);
    sqlite3_bind_text(stmt, 13, entry->attributes, -1, NULL);
    sqlite3_bind_int(stmt, 14, entry->mode);
    sqlite3_bind_int(stmt, 15, entry->last_event);
    sqlite3_bind_int(stmt, 16, entry->entry_type);
    sqlite3_bind_int(stmt, 17, entry->scanned);
    sqlite3_bind_int(stmt, 18, entry->options);
    sqlite3_bind_text(stmt, 19, entry->checksum, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        // Get ID
        sqlite3_prepare_v2(db, LAST_ROWID, -1, &stmt, 0);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int row_id = sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);
            // Insert index
            sqlite3_prepare_v2(db, INSERT_PATH, -1, &stmt, 0);
            sqlite3_bind_int(stmt, 1, row_id);
            sqlite3_bind_int(stmt, 2, file_path);
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

    sqlite3_prepare_v2(db, "SELECT count(*), inode_id FROM inode_path WHERE path = ?", -1, &stmt, NULL);
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
            sqlite3_prepare_v2(db, "DELETE FROM inode_data WHERE rowid = ?", -1, &stmt, NULL);
            sqlite3_bind_text(stmt, 1, sqlite3_column_text(stmt, 1), -1, NULL);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                goto exit_err;
            }
            // Fallthrough
        default:
            // The inode has more entries, delete only this path.
            sqlite3_finalize(stmt);
            sqlite3_prepare_v2(db, "DELETE FROM inode_path WHERE path = ?", -1, &stmt, NULL);
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


int fim_db_remove_inode(const char * inode) {

    sqlite3_stmt *stmt = NULL;

    sqlite3_prepare_v2(db, "SELECT rowid FROM inode_data WHERE inode = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, inode, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int row_id = sqlite3_column_int(stmt, 0);
        // Delete the entry data.
        sqlite3_finalize(stmt);
        sqlite3_prepare_v2(db, "DELETE FROM inode_data WHERE rowid = ?", -1, &stmt, NULL);
        sqlite3_bind_int(stmt, 1, row_id);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            goto exit_err;
        }

        // Delete all paths with this inode.
        sqlite3_finalize(stmt);
        sqlite3_prepare_v2(db, "DELETE FROM inode_path WHERE inode_id = ?", -1, &stmt, NULL);
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


fim_entry_data * fim_db_get_inode(const char * inode) { // mirar -> dev:inode

    sqlite3_stmt *stmt = NULL;

    sqlite3_prepare_v2(db, "SELECT * FROM inode_data WHERE inode = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, inode, -1, NULL);

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
        entry->entry_type = (char *)sqlite3_column_text(stmt, 14); // revisar
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

    sqlite3_prepare_v2(db, "SELECT * FROM inode_data WHERE inode = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, file_path, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_ROW) {

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
        entry->entry_type = (char *)sqlite3_column_text(stmt, 14); // revisar
        entry->scanned = (time_t)sqlite3_column_int(stmt, 15);
        entry->options = (time_t)sqlite3_column_int(stmt, 16);
        entry->checksum = (char *)sqlite3_column_text(stmt, 17);

        sqlite3_finalize(stmt);
        return entry;
    }
    sqlite3_finalize(stmt);
    return NULL;
}


int fim_db_set_not_scanned(void) {

    sqlite3_stmt *stmt = NULL;

    sqlite3_prepare_v2(db, "UPDATE inode_data SET scanned = 0", -1, &stmt, NULL);

    int ret = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        ret = 0;
    }

    sqlite3_finalize(stmt);
    return ret;
}
