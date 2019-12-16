#include <time.h>

typedef struct fim_entry_data {
    // Checksum attributes
    unsigned int size;
    char * perm;
    char * attributes;
    char * uid;
    char * gid;
    char * user_name;
    char * group_name;
    unsigned int mtime;
    unsigned long int inode;
    char * hash_md5;
    char * hash_sha1;
    char * hash_sha256;

    // Options
    unsigned int mode;
    time_t last_event;
    const char * entry_type;
    unsigned long int dev;
    unsigned int scanned;
    int options;
    char * checksum;
} fim_entry_data;

int wdb_create_file(const char *path, const char *source);
