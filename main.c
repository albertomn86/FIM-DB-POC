#include "fim_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <sched.h>

#define TEST_PATH_START "/root/tiempos.csv"
#define TEST_PATH_END "/home/user/test/file_4"
#define PATH_MAX 4096

void fim_path(const char * path);
void fim_dir(int fd, const char * path);
void fim_file(int fd, const char * path, struct stat * statbuf);
#define loop_path(x) (x[0] == '.' && (x[1] == '\0' || (x[1] == '.' && x[2] == '\0')))

int get_all_callback(fim_entry_data *entry) {
    //printf("Path: %s\n", entry->path);

    // Entry destructor call
    return 0;
}

static fim_entry_data *fill_entry_struct(
    const char * path,
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
    data->path = strdup(path);
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
    os_strdup("new_sha256", resp->hash_sha256);
    resp->scanned = 0;
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
        free_entry_data(resp);
        return FIMDB_ERR;
    }

    // Confirm the change
    printf("Database content:\n");
    fim_entry_data *updated_entry = fim_db_get_path(TEST_PATH_START);

    if (!strcmp(updated_entry->path, resp->path) &&
        updated_entry->inode == resp->inode &&
        updated_entry->dev == resp->dev) {
        print_fim_entry_data_full(updated_entry);

    }
    free_entry_data(resp);
    free_entry_data(updated_entry);

    return 0;
}

#define DEF_PATH "/home/user/test/file_"
int fill_entries_random(unsigned int num_entries) {

    unsigned int i = 0;
    for(i = 0; i < num_entries; i++) {
        fim_entry_data *data = fill_entry_struct("", rand(), "rwxrwxrwx", "attrib", "0", "0", "root", "root", rand() % 1500000000, rand() % 200000, "ce6bb0ddf75be26c928ce2722e5f1625", "53bf474924c7876e2272db4a62fc64c8e2c18b51", "c2de156835127560dc1e8139846da7b7d002ac1b72024f6efb345cf27009c54c", rand() % 3, rand() % 1500000000, rand() % 3, rand() % 1024, 0, 137, "ce6bb0ddf75be26c928ce2722e5f1625");
        char * path = calloc(512, sizeof(char));
        snprintf(path, 512, "%s%i", DEF_PATH, i);

        if (fim_db_insert(path, data)) {
            printf("Error in fim_db_insert() function: %s\n", path);
            print_fim_entry_data_full(data);
            return FIMDB_ERR;
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
        fim_entry_data *data = fill_entry_struct(path, size, perm, attributes, uid, gid, user_name, group_name, mtime, inode, hash_md5, hash_sha1, hash_sha256, mode, last_event, entry_type, dev, scanned, options, checksum);
        print_fim_entry_data(data);
        if (callback(path, data)) {
            printf("Error in process_sample_entries() function. PATH: %s\n", path);
            return FIMDB_ERR;
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
        return FIMDB_ERR;
    }

    return 0;
}

int test_fim_insert() {
    if (process_sample_entries(fim_db_insert)) {
        return FIMDB_ERR;
    }

    if (process_sample_entries(fim_verify_sample_entries)) {
        return FIMDB_ERR;
    }

    return 0;
}


void fim_path(const char * path) {

    int fd = open(path, O_RDONLY | O_NONBLOCK);

    if (fd == -1) {
        printf("Cannot open '%s': %s\n", path, strerror(errno));
        return;
    }

    struct stat buf;

    if (fstat(fd, &buf) == -1) {
        printf("Cannot stat '%s': %s\n", path, strerror(errno));
        return;
    }

    switch (buf.st_mode & S_IFMT) {
    case S_IFDIR:
        fim_dir(fd, path);
        break;

    case S_IFREG:
        fim_file(fd, path, &buf);
        break;

    default:
        printf("Ignoring '%s': not a regular file\n", path);
        close(fd);
    }
}


int fim_scan(const char * path) {
    struct stat buf;

    if (lstat(path, &buf) == -1) {
        return -1;
    } else if ((buf.st_mode & S_IFMT) == S_IFLNK) {
        char real[PATH_MAX];

        if (realpath(path, real)) {
            fim_path(real);
        } else {
            return -1;
        }
    } else {
        fim_path(path);
    }

    return 0;
}


void fim_dir(int fd, const char * path) {
    DIR * dir = fdopendir(fd);

    if (dir == NULL) {
        printf("Cannot open directory '%s': %s\n", path, strerror(errno));
    } else {
        struct dirent * entry;

        while ((entry = readdir(dir))) {
            if (!loop_path(entry->d_name)) {
                char lpath[PATH_MAX];
                snprintf(lpath, PATH_MAX, "%s%s%s", path, (path[strlen(path) - 1] == '/') ? "" : "/", entry->d_name);
                //printf("%s\n", lpath);
                fim_path(lpath);
                sched_yield();
            }
        }
    }

    closedir(dir);
}

#define MAX_SIZE 1073741824
void fim_file(int fd, const char * path, struct stat * statbuf) {
    char sha256[65];

    fim_entry_data *data = calloc(1, sizeof(fim_entry_data));


    /* Owner and group */
    struct passwd * owner = getpwuid(statbuf->st_uid);
    if (owner) {
        data->user_name = strdup(owner->pw_name);
    } else {
        data->user_name = strdup("unknown");
    }

    struct group * group = getgrgid(statbuf->st_gid);
    if (owner) {
        data->group_name = strdup(group->gr_name);
    } else {
        data->group_name = strdup("");
    }

    data->path = strdup(path);
    data->size = statbuf->st_size;
    char str_mode[128] = {0};
    snprintf(str_mode, 128, "%i", statbuf->st_mode);
    data->perm = strdup(str_mode);
    data->attributes = strdup("");
    char str_uid[128] = {0};
    snprintf(str_uid, 127, "%i", statbuf->st_uid);
    data->uid = strdup(str_uid);
    char str_gid[128] = {0};
    snprintf(str_gid, 127, "%i", statbuf->st_gid);
    data->gid = strdup(str_gid);

    data->mtime = statbuf->st_mtime;
    data->inode = statbuf->st_ino;
    data->hash_md5 = strdup("1dd614869481a863afa22765ccb5be36");
    data->hash_sha1 = strdup("b304095d3a8d81f7adbd1506e8b69a2dffab6b94");

    data->mode = 1;
    data->last_event = 0;
    data->entry_type = 0;
    data->dev = statbuf->st_dev;
    data->scanned = 1;
    data->options = 0;
    data->checksum = strdup("1dd614869481a863afa22765ccb5be36");


    /* SHA256 */

    if (statbuf->st_size > 0) {
        if (statbuf->st_size > MAX_SIZE) {
            printf("Ignoring '%s' SHA256: file exceeds size limit", path);
        } else if (file_sha256(fd, sha256) == 0) {
            data->hash_sha256 = strdup(sha256);
        } else {
            printf("Cannot calculate SHA256 sum of '%s'", path);
        }
    } else {
        data->hash_sha256 = strdup("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
    //print_fim_entry_data_full(data);
    if (fim_db_insert(path, data)) {
        printf("Error in fim_db_insert() function: %s\n", path);
        print_fim_entry_data_full(data);
        exit(1);
    }
    free_entry_data(data);
    close(fd);
}


int basic_test(const bool type, const char * folder) {

    struct timespec start, end, commit;
    
    announce_function("fim_db_init");

    gettime(&start);

    if (fim_db_init(type) == FIMDB_ERR) {
        merror("Could not init the database.");
        return 1;
    }

    gettime(&end);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    announce_function("test_fim_insert");
    gettime(&start);

    fim_scan(folder);

    gettime(&end);

    fim_force_commit();

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));
}


int main(int argc, char *argv[]) {

    if (argc != 4) {
        fprintf(stderr, "\n./fim_db <type> <folder> <loop-iterations>\n\n"
                        "\t- types{mem|disc}\n");
        return 1;
    }

    nice(10);

    bool type     = (!strcmp("mem", argv[1]))? true : false;
    char * folder = argv[2];
    int    loop   = atoi(argv[3]);

    basic_test(type, folder);

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    announce_function("fim_db_get_path");
    
    int i;
    struct timespec start, end, commit;
    fim_entry_data *respx = NULL;

    gettime(&start);

    for (i = 0; i < loop; i++) {
        respx = fim_db_get_path(TEST_PATH_START);
        if (!respx) {
            merror("Error in fim_db_get_path() function.");
            return 1;
        }
    }

    gettime(&end);

    print_fim_entry_data(respx);
    free_entry_data(respx);

    printf("Time elapsed: %f\n", (double) time_diff(&end, &start));

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
}
