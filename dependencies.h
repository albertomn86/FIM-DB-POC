#include <time.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#define debug_level 0
#define max_size 20000
typedef struct fim_entry_data {
    char *path; // Duda ~~~~~~

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
    int entry_type;
    unsigned long int dev;
    unsigned int scanned;
    int options;
    char * checksum;
} fim_entry_data;

int w_is_file(const char * const file);
int wdb_create_file(const char *path, const char *source);
void mdebug1(const char *msg, ...);
void merror(const char *msg, ...);
uid_t Privsep_GetUser(const char *name) __attribute__((nonnull));
gid_t Privsep_GetGroup(const char *name) __attribute__((nonnull));
#define os_calloc(x,y,z) ((z = (__typeof__(z)) calloc(x,y)))?(void)1:exit(1)
#define os_strdup(x,y) ((y = strdup(x)))?(void)1:exit(1)
#define w_strdup(x,y) ({ int retstr = 0; if (x) { os_strdup(x, y);} else retstr = 1; retstr;})
#define os_free(x) if(x){free(x);x=NULL;}
void free_entry_data(fim_entry_data * data);
#define wdb_finalize(x) { if (x) { sqlite3_finalize(x); x = NULL; } }
#define w_rwlock_init(x, y) { int error = pthread_rwlock_init(x, y); if (error) exit(1); }
#define w_rwlock_rdlock(x) { int error = pthread_rwlock_rdlock(x); if (error) exit(1); }
#define w_rwlock_wrlock(x) { int error = pthread_rwlock_wrlock(x); if (error) exit(1); }
#define w_rwlock_unlock(x) { int error = pthread_rwlock_unlock(x); if (error) exit(1); }
