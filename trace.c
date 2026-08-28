#include <stdio.h>

int main(int argc, char** argv) {

    // take in 1 arg
    if (argc != 2) {
        printf("Usage: ./trace-Linux-x86_64 aTraceFile\n");
        
        return 1; // invalid arg count 
    }
    printf("%s\n", argv[1]);

    return 0;
}

