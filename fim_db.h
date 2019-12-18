#include "dependencies.h"
#include <sqlite3.h>
#include <pthread.h>
#define FIM_DB_PATH "fim.db"

#define DB_ERR -1

extern const char *schema_fim_sql;

const char * fim_db_err_to_str(int err);

typedef enum fdb_stmt {
    FIMDB_STMT_QUERY1,
    FIMDB_STMT_QUERY2,
    FIMDB_STMT_QUERY3,
    WDB_STMT_SIZE
} fdb_stmt;

typedef struct fdb_t {
    sqlite3 * db;
    sqlite3_stmt * stmt[WDB_STMT_SIZE];
    time_t last_commit;
    time_t transaction_interval;
    pthread_rwlock_t mutex;
} fdb_t;

/**
 * @brief Initialize FIM databases.
 * Checks if the databases exists.
 * If it exists deletes the previous version and creates a new one.
 *
 * @return 1 on success, DB_ERROR otherwise.
 */
int fim_db_init(void);


/**
 * @brief Clean the FIM databases.
 *
 * @return 1 on success, DB_ERROR otherwise.
 */
int fim_db_clean(void);


/**
 * @brief Insert a new entry.
 *
 * @param entry Entry data to be inserted.
 * @return 0 on success, DB_ERROR otherwise.
 */
int fim_db_insert(const char* file_path, fim_entry_data *entry);


/**
 * @brief Update/Replace entry.
 *
 * @param device
 * @return 0 on success, DB_ERROR otherwise.
 */
int fim_db_update(const unsigned long int inode, const unsigned long int dev, fim_entry_data *entry);


/**
 * @brief Delete path.
 *
 * @param file_path
 * @return 0 on success, DB_ERROR otherwise.
 */
int fim_db_remove_path(const char * file_path);


/**
 * @brief Delete entry using inode.
 *
 * @param inode
 * @return 1 on success, DB_ERROR otherwise.
 */
int fim_db_remove_inode(const unsigned long int inode, const unsigned long int dev);


/**
 * @brief Get entry data using inode.
 *
 * @param inode Inode
 * @param dev Device
 * @return List of fim_entry_data.
 */
fim_entry_data * fim_db_get_inode(const unsigned long int inode, const unsigned long int dev);


/**
 * @brief Get entry data using path.
 *
 * @param inode
 * @return fim_entry_data
 */
fim_entry_data * fim_db_get_path(const char * file_path);


/**
 * @brief Get all the paths within a range.
 *
 * @param start Starting path.
 * @param end Last included path.
 * @param callback Callback function (fim_checksum_update, fim_file_report).
 * @return 0 on success, DB_ERROR otherwise.
 */
int fim_db_get_range(const char * start, const char * end, int (*callback)(fim_entry_data *));


/**
 * @brief Get all the paths in the DB.
 * This function will return a list with the paths ascending order.
 *
 * @param callback Callback function (fim_checksum_update, fim_file_report).
 * @return 0 on success, DB_ERROR otherwise.
 */
int fim_db_get_all(int (*callback)(fim_entry_data *));


/**
 * @brief Set all files to 'not scanned'.
 *
 */
int fim_db_set_all_unscanned(void);


/**
 * @brief Delete all unescanned entries.
 *
 * @return 0 on success, DB_ERROR otherwise.
 */
int fim_db_delete_unscanned(void);


/**
 * @brief Get all files not scanned.
 *
 * @param callback Callback function (fim_report_deleted).
 */
int fim_db_get_not_scanned(int (*callback)(fim_entry_data *));
