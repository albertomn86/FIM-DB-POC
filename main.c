#include "fim_db.h"
#include <stdio.h>

int get_all_callback(fim_entry_data *entry) {
    mdebug1("Path: %s", entry->path);

    // Entry estructor call
    return 0;
}

void announce_function(char *function) {
    printf("***Testing %s***\n", function);
}

int print_fim_entry_data(fim_entry_data *entry) {
    printf("%s|%i|%s|%s|%s|%s|%s|%s|%i|%li|%s|%s|%s|%i|%li|%i|%lu|%i|%i|%s",
        entry->path,
        entry->size,
        entry->perm,
        entry->attributes,
        entry->uid,
        entry->gid,
        entry->user_name,
        entry->group_name,
        entry->mtime,
        entry->inode,
        entry->hash_md5,
        entry->hash_sha1,
        entry->hash_sha256,
        entry->mode,
        entry->last_event,
        entry->entry_type,
        entry->dev,
        entry->scanned,
        entry->options,
        entry->checksum
    );
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

    announce_function("fim_db_delete_unscanned");
    if (fim_db_delete_unscanned()) {
        merror("Error in fim_db_delete_unscanned() function.");
        return 1;
    }
    mdebug1("~~~~~~~~~ fim_db_get_path ~~~~~~~~~");

    fim_entry_data *resp = fim_db_get_path("/home/user/test/file15");
    print_fim_entry_data(resp);


    return 0;
}
