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

    return 0;
}