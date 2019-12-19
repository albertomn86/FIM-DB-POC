#include "fim_db.h"
#include <stdio.h>
#include <stdlib.h>

#define TEST_PATH_START "/home/user/test/file_1"
#define TEST_PATH_END "/home/user/test/file_4"

int get_all_callback(fim_entry_data *entry) {
    printf("Path: %s\n", entry->path);

    // Entry estructor call
    return 0;
}

static fim_entry_data *fill_entry_struct(
    unsigned int size,
    const char * perm,
    const char * attributes,
    const char * uid,
    const char * gid,
    const char * user_name,
    const char * group_name,
    unsigned int mtime,
    unsigned long int inode,
    const char * hash_md5,
    const char * hash_sha1,
    const char * hash_sha256,
    int mode,
    time_t last_event,
    int entry_type,
    unsigned long int dev,
    unsigned int scanned,
    int options,
    const char * checksum
) {
    fim_entry_data *data = calloc(1, sizeof(fim_entry_data));
    data->size = size;
    data->perm = strdup(perm);
    data->attributes = strdup(attributes);
    data->uid = strdup(uid);
    data->gid = strdup(gid);
    data->user_name = strdup(user_name);
    data->group_name = strdup(group_name);;
    data->mtime = mtime;
    data->inode = inode;
    data->hash_md5 = strdup(hash_md5);
    data->hash_sha1 = strdup(hash_sha1);
    data->hash_sha256 = strdup(hash_sha256);
    data->mode = mode;
    data->last_event = last_event;
    data->entry_type = entry_type;
    data->dev = dev;
    data->scanned = scanned;
    data->options = options;
    data->checksum = strdup(checksum);
    return data;
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

    printf("%s|", entry->path ? entry->path : "" );
    printf("%i|", entry->size);
    printf("%s|", entry->perm ? entry->perm : "" );
    printf("%s|", entry->attributes ? entry->attributes : "" );
    printf("%s|", entry->uid ?  entry->uid : "" );
    printf("%s|", entry->gid ?  entry->gid : "" );
    printf("%s|", entry->user_name ? entry->user_name : "" );
    printf("%s|", entry->group_name ? entry->group_name : "" );
    printf("%i|", entry->mtime);
    printf("%lu|", entry->inode);
    printf("%s|", entry->hash_md5 ? entry->hash_md5 : "" );
    printf("%s|", entry->hash_sha1 ? entry->hash_sha1 : "" );
    printf("%s|", entry->hash_sha256 ? entry->hash_sha256 : "" );
    printf("%i|", entry->mode);
    printf("%lu|", entry->last_event);
    printf("%i|", entry->entry_type);
    printf("%lu|", entry->dev);
    printf("%i|", entry->scanned);
    printf("%i|", entry->options );
    printf("%s\n", entry->checksum ? entry->checksum : "" );

}

int test_fim_db_update() {
    fim_entry_data **resp = fim_db_get_path(TEST_PATH_START);
    if (!resp) {
        return -1;
    }

    int i;
    // Modify the current content
    for (i = 0; resp && resp[i]; i++) {
        resp[i]->size +=100;
        free(resp[i]->perm);
        os_strdup("!!!", resp[i]->perm);
        free(resp[i]->hash_sha256);
        os_strdup("new_sha256", resp[i]->hash_sha256);
        resp[i]->scanned = 1;
        free(resp[i]->checksum);
        os_strdup("====", resp[i]->checksum);

        // Declaration of intentions
        printf("New attrs for '%s'\n" \
                " - Size: %u\n" \
                " - Perm: %s\n" \
                " - Sha256: %s\n" \
                " - Scanned: %u\n" \
                " - Checksum: %s\n",
                resp[i]->path, resp[i]->size, resp[i]->perm, resp[i]->hash_sha256, resp[i]->scanned, resp[i]->checksum);

        // Update the database
        if (fim_db_update(resp[i]->inode, resp[i]->dev, resp[i])) {
            return DB_ERR;
        }

        // Confirm the change
        printf("Database content:\n");
        fim_entry_data **updated_entry = fim_db_get_path(TEST_PATH_START);
        int j;
        for (j = 0; updated_entry && updated_entry[j]; j++) {
            if (!strcmp(updated_entry[j]->path, resp[i]->path) &&
                updated_entry[j]->inode == resp[i]->inode &&
                updated_entry[j]->dev == resp[i]->dev) {
                print_fim_entry_data_full(updated_entry[j]);
                break;
            }
        }
    }

    return 0;
}

#define DEF_PATH "/home/user/test/file_"
int fill_entries_random(unsigned int num_entries) {

    unsigned int i = 0;
    for(i = 0; i < num_entries; i++) {
        fim_entry_data *data = fill_entry_struct(rand(), "rwxrwxrwx", "attrib", "0", "0", "root", "root", rand() % 1500000000, rand() % 1024, "ce6bb0ddf75be26c928ce2722e5f1625", "53bf474924c7876e2272db4a62fc64c8e2c18b51", "c2de156835127560dc1e8139846da7b7d002ac1b72024f6efb345cf27009c54c", rand() % 3, rand() % 1500000000, rand() % 3, rand() % 1024, 0, 137, "ce6bb0ddf75be26c928ce2722e5f1625");
        char * path = calloc(512, sizeof(char));
        snprintf(path, 512, "%s%i", DEF_PATH, i);
        if (fim_db_insert(path, data)) {
            printf("Error in fim_db_insert() function.");
            return DB_ERR;
        }
        free_entry_data(data);
        free(path);
    }

    return 0;
}

int process_sample_entries(int (*callback)(const char *path, fim_entry_data *data)) {
    FILE *fp;

    fp = fopen("sample_entries.txt", "r"); // read mode

    if (fp == NULL)
    {
        merror("Error while opening the file.\n");
        return -1;
    }

    char path[512];
    int size;
    char attributes[128] = "---------------";
    char perm[128];
    char uid[5];
    char gid[5];
    char user_name[64];
    char group_name[64];
    unsigned int mtime;
    unsigned long int inode;
    char hash_md5[33];
    char hash_sha1[41];
    char hash_sha256[64];
    int mode;
    time_t last_event;
    int entry_type;
    unsigned long int dev;
    unsigned int scanned;
    int options;
    char checksum[33];

    char line[2048];

    while(fgets(line, 2048, fp)) {
        sscanf(line, "%s %u %s %s %s %s %s %s %u %ld %s %s %s %i %lu %i %ld %u %i %s",\
            path, &size, perm, attributes, uid, gid, user_name, group_name, &mtime, &inode, hash_md5, hash_sha1, hash_sha256, &mode, &last_event, &entry_type, &dev, &scanned, &options, checksum);
        fim_entry_data *data = fill_entry_struct(size, perm, attributes, uid, gid, user_name, group_name, mtime, inode, hash_md5, hash_sha1, hash_sha256, mode, last_event, entry_type, dev, scanned, options, checksum);
        print_fim_entry_data(data);
        if (callback(path, data)) {
            printf("Error in process_sample_entries() function. PATH: %s", path);
            return DB_ERR;
        }
        free_entry_data(data);
    }

    fclose(fp);
    return 0;
}

int fim_verify_sample_entries(const char *file_path, fim_entry_data *entry) {
   fim_entry_data *saved_file = fim_db_get_unique_file(file_path, entry->inode, entry->dev);

    if (!saved_file ||
        entry->size != saved_file->size ||
        entry->mtime != saved_file->mtime ||
        entry->inode != saved_file->inode ||
        entry->mode != saved_file->mode ||
        entry->last_event != saved_file->last_event ||
        entry->entry_type != saved_file->entry_type ||
        entry->dev != saved_file->dev ||
        entry->scanned != saved_file->scanned ||
        entry->options != saved_file->options ||
        strcmp(entry->perm, saved_file->perm) ||
        strcmp(entry->attributes, saved_file->attributes) ||
        strcmp(entry->uid, saved_file->uid) ||
        strcmp(entry->gid, saved_file->gid) ||
        strcmp(entry->user_name, saved_file->user_name) ||
        strcmp(entry->group_name, saved_file->group_name) ||
        strcmp(entry->hash_md5, saved_file->hash_md5) ||
        strcmp(entry->hash_sha1, saved_file->hash_sha1) ||
        strcmp(entry->hash_sha256, saved_file->hash_sha256) ||
        strcmp(entry->checksum, saved_file->checksum)) {
        return DB_ERR;
    }

    return 0;
}

int test_fim_insert() {
    if (process_sample_entries(fim_db_insert)) {
        return DB_ERR;
    }

    if (process_sample_entries(fim_verify_sample_entries)) {
        return DB_ERR;
    }

    return 0;
}

int main() {
    announce_function("fim_db_init");
    if (fim_db_init() == DB_ERR) {
        merror("Could not init the database.");
        return 1;
    }

    announce_function("test_fim_insert");
    /*
    if (test_fim_insert()) {
        merror("Error in test_fim_insert() function.");
        return 1;
    }
    */

    announce_function("fill_entries_random");
    if (fill_entries_random(100)) {
        merror("Error in fill_entries_random() function.");
        return 1;
    }

    announce_function("fim_db_get_all");
    if (fim_db_get_all(get_all_callback)) {
        merror("Error in fim_db_get_all() function.");
        return 1;
    }

    announce_function("fim_db_get_range");
    if (fim_db_get_range(TEST_PATH_START, TEST_PATH_END, get_all_callback)) {
        merror("Error in fim_db_get_range() function.");
        return 1;
    }

    announce_function("fim_db_set_all_unscanned");
    if (fim_db_set_all_unscanned()) {
        merror("Error in fim_db_set_all_unscanned() function.");
        return 1;
    }

    announce_function("fim_db_get_path");
    fim_entry_data **resp = fim_db_get_path(TEST_PATH_START);
    unsigned int i;
    if (!resp) {
        merror("Error in fim_db_get_path() function.");
        return 1;
    }
    for (i = 0; resp[i]; i++) {
        print_fim_entry_data(resp[i]);
        free_entry_data(resp[i]);
    }
    free(resp);

    announce_function("fim_db_update");
    if (test_fim_db_update()) {
        merror("Error in fim_db_update() function.");
        return 1;
    }

    announce_function("fim_db_get_not_scanned");
    if (fim_db_get_not_scanned(get_all_callback)) {
        merror("Error in fim_db_get_not_scanned() function.");
        return 1;
    }

    fim_force_commit(); // ~~~~~~~~~~~~~

    announce_function("fim_db_get_inode");
    fim_entry_data **resp2 = fim_db_get_inode(1234, 1);
    unsigned int j;
    if (!resp2) {
        merror("Error in fim_db_get_inode() function.");
        return 1;
    }
    for (j = 0; resp2[j]; j++) {
        print_fim_entry_data(resp2[j]);
        free_entry_data(resp2[j]);
    }
    free(resp2);

    announce_function("fim_db_delete_unscanned");
    if (fim_db_delete_unscanned()) {
        merror("Error in fim_db_delete_unscanned() function.");
        return 1;
    }

    return 0;
}
