#include <stdio.h>
#include <stdlib.h>
#include "counter/counter.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <counter_name>\n", argv[0]);
        return 1;
    }

    return print_counter(argv[1]);
}
