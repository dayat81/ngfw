#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <rocksdb/c.h>
#include <arpa/inet.h>

rocksdb_t* init_db(const char* db_path, int read_only, char** err) {
    rocksdb_options_t* options = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(options, !read_only);
    
    rocksdb_t* db;
    if (read_only) {
        db = rocksdb_open_for_read_only(options, db_path, 0, err);
    } else {
        rocksdb_options_set_error_if_exists(options, 0);
        rocksdb_options_set_write_buffer_size(options, 64 * 1024 * 1024);
        db = rocksdb_open(options, db_path, err);
    }
    
    rocksdb_options_destroy(options);
    return db;
}

void close_db(rocksdb_t* db) {
    rocksdb_close(db);
}

int print_blacklist(void) {
    const char* db_path = "/tmp/blacklist.db";
    
    char* err = NULL;
    rocksdb_t* db = init_db(db_path, 1, &err);
    if (err != NULL) {
        fprintf(stderr, "Failed to open RocksDB: %s\n", err);
        free(err);
        return 1;
    }

    // Iterate through the database
    rocksdb_iterator_t* iter = rocksdb_create_iterator(db, rocksdb_readoptions_create());
    rocksdb_iter_seek_to_first(iter);

    while (rocksdb_iter_valid(iter)) {
        size_t key_len;
        const char* key = rocksdb_iter_key(iter, &key_len);
        //const char* value = rocksdb_iter_value(iter, &value_len);

        // Process the key-value pair
        printf("Blacklisted IP: %.*s\n", (int)key_len, key);
        rocksdb_iter_next(iter);
    }

    // Clean up
    rocksdb_iter_destroy(iter);
    close_db(db);

    return 0;
}

int is_valid_ip(const char* ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

int insert_ip(const char* ip) {
    if (!is_valid_ip(ip)) {
        fprintf(stderr, "Invalid IP address format: %s\n", ip);
        return 1;
    }

    const char* db_path = "/tmp/blacklist.db";
    
    char* err = NULL;
    rocksdb_t* db = init_db(db_path, 0, &err);
    if (err != NULL) {
        fprintf(stderr, "Failed to open RocksDB: %s\n", err);
        free(err);
        return 1;
    }

    // Insert the IP
    rocksdb_writeoptions_t* writeoptions = rocksdb_writeoptions_create();
    rocksdb_put(db, writeoptions, ip, strlen(ip), "1", 1, &err);  // Use "1" as value
    if (err != NULL) {
        fprintf(stderr, "Failed to insert IP: %s\n", err);
        free(err);
        rocksdb_writeoptions_destroy(writeoptions);
        close_db(db);
        return 1;
    }

    // Clean up
    rocksdb_writeoptions_destroy(writeoptions);
    close_db(db);

    printf("IP %s has been blacklisted.\n", ip);
    return 0;
}

int clear_blacklist(void) {
    const char* db_path = "/tmp/ramdisk/blacklist.db";
    
    char* err = NULL;
    rocksdb_t* db = init_db(db_path, 0, &err);
    if (err != NULL) {
        fprintf(stderr, "Failed to open RocksDB: %s\n", err);
        free(err);
        return 1;
    }

    // Iterate and delete all entries
    rocksdb_iterator_t* iter = rocksdb_create_iterator(db, rocksdb_readoptions_create());
    rocksdb_writeoptions_t* writeoptions = rocksdb_writeoptions_create();

    for (rocksdb_iter_seek_to_first(iter); rocksdb_iter_valid(iter); rocksdb_iter_next(iter)) {
        size_t key_len;
        const char* key = rocksdb_iter_key(iter, &key_len);
        
        rocksdb_delete(db, writeoptions, key, key_len, &err);
        if (err != NULL) {
            fprintf(stderr, "Failed to delete key: %s\n", err);
            free(err);
            err = NULL;
            // Continue with the next key
        }
    }

    // Clean up
    rocksdb_iter_destroy(iter);
    rocksdb_writeoptions_destroy(writeoptions);
    close_db(db);

    printf("Blacklist has been cleared.\n");
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc == 2 && strcmp(argv[1], "print") == 0) {
        return print_blacklist();
    } else if (argc == 3 && strcmp(argv[1], "insert") == 0) {
        return insert_ip(argv[2]);
    } else if (argc == 2 && strcmp(argv[1], "clear") == 0) {
        return clear_blacklist();
    } else {
        fprintf(stderr, "Usage: %s print\n       %s insert <ip>\n       %s clear\n", argv[0], argv[0], argv[0]);
        return 1;
    }
}
