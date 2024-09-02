#!/bin/bash

# Compile the shared library source code
gcc -Wall -fPIC -c /home/dhimant/Desktop/project_folder/server_lib/cosc_6325_hash.c -o /home/dhimant/Desktop/project_folder/server_lib/cosc_6325_hash.o

# Create the shared library from the object file
gcc -shared -o /home/dhimant/Desktop/project_folder/server_lib/libcosc_6325_hash.so /home/dhimant/Desktop/project_folder/server_lib/cosc_6325_hash.o

# Remove the object file after creating the shared library
rm /home/dhimant/Desktop/project_folder/server_lib/cosc_6325_hash.o
