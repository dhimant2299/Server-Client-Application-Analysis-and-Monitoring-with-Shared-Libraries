README

Overview
This project contains several components related to server-client application analysis and monitoring. It includes functionalities for tracing syscalls, analyzing server activities, and managing shared libraries. Below are the main components and instructions for building and running them.

Components
client_analysis_version.c: Source code for the client analysis version.
server_analysis_version.c: Source code for the server analysis version.
redirect_server_analysis_version.c: Source code for the redirect server analysis version.
tracer.c: Source code for the tracer application.

Makefile: Makefile for compiling the project components.

For the part two "Shared Libraries"
analysis_script.sh: Script for server analysis.
modify_shared_lib.c: Script for modifying the shared library.
compile_lib.sh: Script for compiling the shared library.

Compiling Instructions

Navigate to the project root directory.
Run make to compile all source files and create executables.
After compilation, the following executables will be created:

client_analysis_version: Client analysis version executable.
server_analysis_version: Server analysis version executable.
redirect_server_analysis_version: Redirect server analysis version executable.
tracer: Tracer application executable.

Special Instructions
Make sure to update paths and configurations as necessary in the source files and scripts.

The screenshots of the tests conducted are in the screenshots_of_tests_conducted folder.

****
about the application's working mechanism:
The project involves the development of a server application with analysis capabilities, designed to handle client interactions and perform server-side operations. The server's functionality includes user authentication using a CSV file located at 'Desktop/project_folder/server_analysis_version/users_and_passwords.csv'. Additionally, the project incorporates shared library functionality, with source code and header files stored in 'Desktop/project_folder/server_lib/'. The server analysis version and redirect server analysis version executables, located respectively at 'Desktop/project_folder/server_analysis_version/server_analysis_version' and 'Desktop/project_folder/server_analysis_version/redirect_server_analysis_version', enable different modes of analysis depending on the command-line argument '-c' for client analysis, '-s' for server analysis, or '-rs' for redirect server analysis. Supporting scripts like 'analysis_script.sh', 'modify_shared_lib.c', 'compile_lib.sh', and 'restart_server.sh' facilitate server management, shared library modification, compilation, and server restarts. This comprehensive setup allows for the development, testing, and maintenance of a robust server application with analysis functionalities.

The project also included the implementation of a shared library, cosc_6325_hash, which provided hashing functionality for password storage and validation. This shared library was utilized by the server application for secure handling of user passwords. Additionally, the project involved the development of scripts for managing the server, modifying the shared library, compiling the library, and restarting the server as needed.



