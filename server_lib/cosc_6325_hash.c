#include "cosc_6325_hash.h"
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

void freeme(BYTE *bytes) {
    free(bytes);
}

bool verify_password(BYTE password_hash[], BYTE *password, const int password_length) {
    BYTE *compare_hash = sha256_digest(password, password_length);
    const bool pass = !memcmp(password_hash, compare_hash, SHA256_BLOCK_SIZE);
    free(compare_hash);

    // Open the output file in append mode
    FILE *output_file = fopen("/home/dhimant/Desktop/project_folder/server_analysis_version/output_data.csv", "a");
    if (output_file == NULL) {
        perror("Error opening output file");
        return false; // Return false if file opening fails
    }

    // Write data to the output CSV file
    fprintf(output_file, "%s,%s,%s,%s\n", "Username", "Password", "Hash", pass ? "Success" : "Failure");

    // Close the output file
    fclose(output_file);

    return pass;

