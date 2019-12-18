#include "fim_db.h"
#include <stdio.h>
#include <stdlib.h>

#define TEST_PATH_START "/home/user/test/file2"
#define TEST_PATH_END "/home/user/test/file4"

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
    fim_entry_data *resp = fim_db_get_path(TEST_PATH_START);
    if (!resp) {
        return -1;
    }

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
    fim_entry_data *updated_entry = fim_db_get_path(TEST_PATH_START);
    if (updated_entry) {
        print_fim_entry_data(updated_entry);
    }

    return 0;
}

int fill_entries() {

    FILE *fp;

    fp = fopen("sample_entries.txt", "r"); // read mode

    if (fp == NULL)
    {
        merror("Error while opening the file.\n");
        return -1;
    }

    char path[512];
    unsigned int size;
    char perm[128];
    char attributes[128];
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
        if (fim_db_insert(path, data)) {
            printf("Error in fim_db_insert() function. PATH: %s", path);
        }
        free_entry_data(data);
    }

    fclose(fp);
    return 0;
}

int main() {
    announce_function("fim_db_init");
    if (fim_db_init() == DB_ERR) {
        merror("Could not init the database.");
        return 1;
    }

    announce_function("fim_db_insert");
    if (fill_entries()) {
        merror("Error in fill_entries() function.");
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
    fim_entry_data *resp = fim_db_get_path(TEST_PATH_START);
    unsigned int i = 0;
    if (!resp) {
        merror("Error in fim_db_get_path() function.");
        return 1;
    }
    while (resp[i++].path) {
        print_fim_entry_data(resp);
        free_entry_data(resp);
    }

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

    announce_function("fim_db_get_inode");
    fim_entry_data *resp2 = fim_db_get_inode(9812, 12);
    unsigned int j = 0;
    if (!resp2) {
        merror("Error in fim_db_get_inode() function.");
        return 1;
    }
    while (resp2[j++].path) {
        print_fim_entry_data(resp2);
        free_entry_data(resp2);
    }

    announce_function("fim_db_delete_unscanned");
    if (fim_db_delete_unscanned()) {
        merror("Error in fim_db_delete_unscanned() function.");
        return 1;
    }

    return 0;
}
