#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "cosc_6325_hash.h"

typedef bool (*VerifyPasswordFunc)(BYTE[], BYTE *, const int);

int main() {
    // Load the shared library
    void *handle = dlopen("./server_lib/libcosc_6325_hash.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Error: %s\n", dlerror());
        return 1;
    }

    // Get the address of the verify_password function from the library
    VerifyPasswordFunc verify_password = dlsym(handle, "verify_password");
    if (!verify_password) {
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return 1;
    }

    // Open the CSV file for writing
    FILE *csv_file = fopen("password_verification_log.csv", "w");
    if (!csv_file) {
        fprintf(stderr, "Error: Unable to open CSV file\n");
        dlclose(handle);
        return 1;
    }

    // Write header to the CSV file
    fprintf(csv_file, "Username, Password, Comparison Hash, Success\n");

   
    const char *username = "test_user";
    BYTE password_hash[SHA256_BLOCK_SIZE];
    BYTE *password = (BYTE *)"test_password";
    const int password_length = strlen((const char *)password);

    // Call the original verify_password function
    bool success = verify_password(password_hash, password, password_length);

    // Write data to CSV file
    fprintf(csv_file, "%s, %s, %s, %s\n", username, password, password_hash, success ? "Success" : "Failure");

    // Close the CSV file and unload the shared library
    fclose(csv_file);
    dlclose(handle);

    return 0;
}
