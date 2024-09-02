# Define compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g

# Define directories
SRC_DIR = src
LIB_DIR = server_lib
OBJ_DIR = obj
BIN_DIR = bin

# Define source files
CLIENT_SRC = $(SRC_DIR)/client_analysis_version.c
SERVER_SRC = $(SRC_DIR)/server_analysis_version.c
REDIRECT_SRC = $(SRC_DIR)/redirect_server_analysis_version.c
LIB_SRC = $(LIB_DIR)/cosc_6325_hash.c

# Define object files
CLIENT_OBJ = $(OBJ_DIR)/client_analysis_version.o
SERVER_OBJ = $(OBJ_DIR)/server_analysis_version.o
REDIRECT_OBJ = $(OBJ_DIR)/redirect_server_analysis_version.o -ldl
LIB_OBJ = $(OBJ_DIR)/cosc_6325_hash.o

# Define executable names
CLIENT_EXE = $(BIN_DIR)/client_analysis_version
SERVER_EXE = $(BIN_DIR)/server_analysis_version
REDIRECT_EXE = $(BIN_DIR)/redirect_server_analysis_version

# Define shared object file
LIB_SO = $(LIB_DIR)/libcosc_6325_hash.so

all: $(CLIENT_EXE) $(SERVER_EXE) $(REDIRECT_EXE) $(LIB_SO)

# Compile client executable
$(CLIENT_EXE): $(CLIENT_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compile server executable
$(SERVER_EXE): $(SERVER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compile redirect server executable
$(REDIRECT_EXE): $(REDIRECT_OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compile shared object file
$(LIB_SO): $(LIB_OBJ)
	$(CC) -shared -o $@ $^

# Compile client object file
$(CLIENT_OBJ): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile server object file
$(SERVER_OBJ): $(SERVER_SRC)
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile redirect server object file
$(REDIRECT_OBJ): $(REDIRECT_SRC)
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile shared object file object
$(LIB_OBJ): $(LIB_SRC)
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

clean:
	rm -rf $(OBJ_DIR)/*.o $(LIB_SO) $(BIN_DIR)/*

.PHONY: all clean
