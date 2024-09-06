#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <rocksdb/c.h>


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <counter_name>\n", argv[0]);
        return 1;
    }

    char db_path[256];
    snprintf(db_path, sizeof(db_path), "/tmp/rocksdb_counter_%s", argv[1]);
    
    rocksdb_t* db;
    rocksdb_options_t* options;
    char* err = NULL;

    // Open RocksDB in read-only mode
    options = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(options, 0);
    db = rocksdb_open_for_read_only(options, db_path, 0, &err);
    if (err != NULL) {
        fprintf(stderr, "Failed to open RocksDB: %s\n", err);
        return 1;
    }

    // Iterate through the database
    rocksdb_iterator_t* iter = rocksdb_create_iterator(db, rocksdb_readoptions_create());
    rocksdb_iter_seek_to_first(iter);

    while (rocksdb_iter_valid(iter)) {
        size_t key_len, value_len;
        const char* key = rocksdb_iter_key(iter, &key_len);
        const char* value = rocksdb_iter_value(iter, &value_len);

        // Process the key-value pair
        // You'll need to implement logic to parse and print the data
        printf("Key: %.*s, Value: %.*s\n", (int)key_len, key, (int)value_len, value);
        rocksdb_iter_next(iter);
    }

    // Clean up
    rocksdb_iter_destroy(iter);
    rocksdb_close(db);
    rocksdb_options_destroy(options);

    return 0;
}
