#ifndef COSC_6325_HASH_LIBRARY_H
#define COSC_6325_HASH_LIBRARY_H

#include "../hash/sha256.h"
#include <stdbool.h>

bool verify_password(BYTE password_hash[], BYTE *password, int password_length);
void freeme(BYTE *bytes);

#endif //COSC_6325_HASH_LIBRARY_H
