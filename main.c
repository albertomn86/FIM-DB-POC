#include "fim_db.h"

int get_all_callback() {

    return 0;
}

int main() {
    if (fim_db_init() == DB_ERR) {
        merror("Could not init the database.");
    }

    fim_db_get_all(get_all_callback);

    return 0;
}