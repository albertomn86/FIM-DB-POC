#include "dependencies.h"

#include <sys/types.h>
#include <sqlite3.h>
#include <errno.h>

/* COPIADA PARA LA PRUEBA */
int wdb_create_file(const char *path, const char *source) {
    const char *ROOT = "root";
    const char *GROUPGLOBAL = "root";
    const char *sql;
    const char *tail;

    sqlite3 *db;
    sqlite3_stmt *stmt;
    int result;
    uid_t uid;
    gid_t gid;

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        mdebug1("Couldn't create SQLite database '%s': %s", path, sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return -1;
    }

    for (sql = source; sql && *sql; sql = tail) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            mdebug1("Preparing statement: %s", sqlite3_errmsg(db));
            sqlite3_close_v2(db);
            return -1;
        }

        result = sqlite3_step(stmt);

        switch (result) {
        case SQLITE_MISUSE:
        case SQLITE_ROW:
        case SQLITE_DONE:
            break;
        default:
            mdebug1("Stepping statement: %s", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            sqlite3_close_v2(db);
            return -1;
        }

        sqlite3_finalize(stmt);
    }

    sqlite3_close_v2(db);

    switch (getuid()) {
    case -1:
        merror("getuid(): %s (%d)", strerror(errno), errno);
        return -1;

    case 0:
        uid = Privsep_GetUser(ROOT);
        gid = Privsep_GetGroup(GROUPGLOBAL);

        if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
            merror("USER_ERROR", ROOT, GROUPGLOBAL);
            return -1;
        }

        if (chown(path, uid, gid) < 0) {
            merror("CHOWN_ERROR", path, errno, strerror(errno));
            return -1;
        }

        break;

    default:
        mdebug1("Ignoring chown when creating file from SQL.");
        break;
    }

    if (chmod(path, 0660) < 0) {
        merror("CHMOD_ERROR", path, errno, strerror(errno));
        return -1;
    }

    return 0;
}
