#include <stdlib.h>

// gcc -c -ggdb types.c -o types.o

#define path_max 4096
#define name_max 20
#define file_max 65535

typedef struct entry entry;
typedef struct directory_entry directory_entry;
typedef struct file_entry file_entry;
typedef struct link_entry link_entry;
typedef struct link_table_entry link_table_entry;

enum entry_type
{
    INVALID_ENTRY = 0x0,
    DIRECTORY_ENTRY = 0x1,
    FILE_ENTRY = 0x2,
    LINK_ENTRY = 0x4,
    DIRECTORY_LINK_ENTRY = DIRECTORY_ENTRY | LINK_ENTRY,
    FILE_LINK_ENTRY = FILE_ENTRY | LINK_ENTRY,
};

struct entry
{
    struct directory_entry *parent_directory;
    enum entry_type type;
    char name[name_max];
};

struct directory_entry
{
    struct entry entry;

    size_t child_count;
    struct entry *child[];
};

struct file_entry
{
    struct entry entry;

    size_t size;
    char *data;
};

struct link_entry
{
    struct entry entry;

    struct entry *target;
};

struct entry a;
struct directory_entry b;
struct file_entry c;
struct link_entry d;
