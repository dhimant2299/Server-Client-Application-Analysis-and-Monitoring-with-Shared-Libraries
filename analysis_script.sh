#!/bin/bash

# Change directory to the server root directory
cd /home/dhimant/Desktop/project_folder/src

# List shared libraries used by the server executable
echo "Shared libraries used by the server executable are:"
ldd server.py

# Examine functions and symbols in shared libraries
echo "Functions and symbols in shared libraries are:"
nm -D /home/dhimant/Desktop/project_folder/server_lib/libcosc_6325_hash.so
objdump -T /home/dhimant/Desktop/project_folder/server_lib/libcosc_6325_hash.so
