#include "dependencies.h"

#include <sys/types.h>
#include <sqlite3.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

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
        printf("Couldn't create SQLite database '%s': %s", path, sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return -1;
    }

    for (sql = source; sql && *sql; sql = tail) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            printf("Preparing statement: %s", sqlite3_errmsg(db));
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
            printf("Stepping statement: %s", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            sqlite3_close_v2(db);
            return -1;
        }

        sqlite3_finalize(stmt);
    }

    sqlite3_close_v2(db);

    switch (getuid()) {
    case -1:
        printf("getuid(): %s (%d)", strerror(errno), errno);
        return -1;

    case 0:
        uid = Privsep_GetUser(ROOT);
        gid = Privsep_GetGroup(GROUPGLOBAL);

        if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
            printf("USER_ERROR");
            return -1;
        }

        if (chown(path, uid, gid) < 0) {
            printf("CHOWN_ERROR");
            return -1;
        }

        break;

    default:
        printf("Ignoring chown when creating file from SQL.");
        break;
    }

    if (chmod(path, 0660) < 0) {
        printf("CHMOD_ERROR");
        return -1;
    }

    return 0;
}

/* Check if a file exists */
int w_is_file(const char * const file)
{
    FILE *fp;
    fp = fopen(file, "r");
    if (fp) {
        fclose(fp);
        return (1);
    }
    return (0);
}

void mdebug1(const char *msg, ...) {
    if (debug_level >= 1) {
        va_list ap;
        va_start(ap, msg);
        char buffer[max_size];
        vsnprintf(buffer, max_size, msg, ap);
        time_t t = time(NULL);
        struct tm *tm_info = localtime(&t);
        char timestamp[26];
        strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(stdout, "%s %s\n", timestamp, buffer);
        va_end(ap);
    }
}

void mdebug2(const char *msg, ...) {
    if (debug_level >= 2) {
        va_list ap;
        va_start(ap, msg);
        char buffer[max_size];
        vsnprintf(buffer, max_size, msg, ap);
        time_t t = time(NULL);
        struct tm *tm_info = localtime(&t);
        char timestamp[26];
        strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(stdout, "%s %s\n", timestamp, buffer);
        va_end(ap);
    }
}

void merror(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    char buffer[max_size];
    vsnprintf(buffer, max_size, msg, ap);
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char timestamp[26];
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(stdout, "%s %s\n", timestamp, buffer);
    va_end(ap);
}

uid_t Privsep_GetUser(const char *name)
{
    struct passwd *pw;
    pw = getpwnam(name);
    if (pw == NULL) {
        return ((uid_t)-1);
    }

    return (pw->pw_uid);
}

gid_t Privsep_GetGroup(const char *name)
{
    struct group *grp;
    grp = getgrnam(name);
    if (grp == NULL) {
        return ((gid_t)-1);
    }

    return (grp->gr_gid);
}


void free_entry_data(fim_entry_data * data) {
    if (!data) {
        return;
    }
    if (data->perm) {
        os_free(data->perm);
    }
    if (data->attributes) {
        os_free(data->attributes);
    }
    if (data->uid) {
#ifdef WIN32
        LocalFree(data->uid);
#else
        os_free(data->uid);
#endif
    }
    if (data->gid) {
        os_free(data->gid);
    }
    if (data->user_name) {
        os_free(data->user_name);
    }
    if (data->group_name) {
        os_free(data->group_name);
    }

    os_free(data);
}
