#include "fim_db.h"


int main() {
    if (fim_db_init() == DB_ERR) {
        merror("Could not init the database.");
    }

    return 0;
}