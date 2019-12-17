#include "fim_db.h"
#include <stdio.h>
#include <stdlib.h>

#define TEST_PATH "/home/user/test/file15"

int get_all_callback(fim_entry_data *entry) {
    printf("Path: %s\n", entry->path);

    // Entry estructor call
    return 0;
}

void announce_function(char *function) {
    printf("\n***Testing %s***\n", function);
}

int print_fim_entry_data_full(fim_entry_data *entry) {

    printf("PATH: %s\n", entry->path);
    printf("SIZE: %i\n", entry->size);
    printf("PERM: %s\n", entry->perm);
    printf("ATTRB: %s\n", entry->attributes);
    printf("UID: %s\n", entry->uid);
    printf("GID: %s\n", entry->gid);
    printf("UNAME: %s\n", entry->user_name);
    printf("GNAME: %s\n", entry->group_name);
    printf("MTIME: %i\n", entry->mtime);
    printf("INODE: %lu\n", entry->inode);
    printf("MD5: %s\n", entry->hash_md5);
    printf("SHA1: %s\n", entry->hash_sha1);
    printf("SHA256: %s\n", entry->hash_sha256);
    printf("MODE: %i\n", entry->mode);
    printf("LAST: %lu\n", entry->last_event);
    printf("ENTRY: %i\n", entry->entry_type);
    printf("DEV: %lu\n", entry->dev);
    printf("SCANNED: %i\n", entry->scanned);
    printf("OPTIONS: %i\n", entry->options);
    printf("CHECKSUM: %s\n", entry->checksum);

}

int print_fim_entry_data(fim_entry_data *entry) {

    printf("%s|", entry->path);
    printf("%i|", entry->size);
    printf("%s|", entry->perm);
    printf("%s|", entry->attributes);
    printf("%s|", entry->uid);
    printf("%s|", entry->gid);
    printf("%s|", entry->user_name);
    printf("%s|", entry->group_name);
    printf("%i|", entry->mtime);
    printf("%lu|", entry->inode);
    printf("%s|", entry->hash_md5);
    printf("%s|", entry->hash_sha1);
    printf("%s|", entry->hash_sha256);
    printf("%i|", entry->mode);
    printf("%lu|", entry->last_event);
    printf("%i|", entry->entry_type);
    printf("%lu|", entry->dev);
    printf("%i|", entry->scanned);
    printf("%i|", entry->options);
    printf("%s\n", entry->checksum);

}

int test_fim_db_update(fim_entry_data *resp) {
    // Modify the current content
    resp->size +=100;
    free(resp->perm);
    os_strdup("!!!", resp->perm);
    free(resp->hash_sha256);
    os_strdup("new_sha256", resp->perm);
    resp->scanned = 1;
    free(resp->checksum);
    os_strdup("====", resp->checksum);

    // Declaration of intentions
    printf("New attrs for '%s'\n" \
            " - Size: %u\n" \
            " - Perm: %s\n" \
            " - Sha256: %s\n" \
            " - Scanned: %u\n" \
            " - Checksum: %s\n",
            resp->path, resp->size, resp->perm, resp->hash_sha256, resp->scanned, resp->checksum);

    // Update the database
    if (fim_db_update(resp->inode, resp->dev, resp)) {
        return DB_ERR;
    }

    // Confirm the change
    printf("Database content:\n");
    fim_entry_data *updated_entry = fim_db_get_path(TEST_PATH);
    if (updated_entry) {
        print_fim_entry_data(updated_entry);
    }
}

int main() {
    announce_function("fim_db_init");
    if (fim_db_init() == DB_ERR) {
        merror("Could not init the database.");
        return 1;
    }

    announce_function("fim_db_get_all");
    if (fim_db_get_all(get_all_callback)) {
        merror("Error in fim_db_get_all() function.");
        return 1;
    }


    announce_function("fim_db_get_range");
    if (fim_db_get_range("/home/user/test/file15", "/home/user/test/file3", get_all_callback)) { // Reemplazar por los paths de test. Estos son de mis pruebas ~~~~~~~~~~~~~~~~~~~~~~~
        merror("Error in fim_db_get_range() function.");
        return 1;
    }

    announce_function("fim_db_set_all_unscanned");
    if (fim_db_set_all_unscanned()) {
        merror("Error in fim_db_set_all_unscanned() function.");
        return 1;
    }

    announce_function("fim_db_get_path");
    fim_entry_data *resp = fim_db_get_path(TEST_PATH);
    if (resp) {
        print_fim_entry_data(resp);
    } else {
        printf("Not found\n");
    }

    announce_function("fim_db_update");
    if (test_fim_db_update(resp)) {
        merror("Error in fim_db_update() function.");
        return 1;
    }

/*
    announce_function("fim_db_delete_unscanned");
    if (fim_db_delete_unscanned()) {
        merror("Error in fim_db_delete_unscanned() function.");
        return 1;
    }
*/

    return 0;
}
