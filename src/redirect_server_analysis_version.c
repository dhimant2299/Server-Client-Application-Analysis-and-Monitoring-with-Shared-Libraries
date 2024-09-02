#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <sys/uio.h>
#include <sys/types.h>
#include "sha256.h"



#define MAX_BUFFER_SIZE 1024
char request_buffer[MAX_BUFFER_SIZE]; 


const char *get_syscall_name(long syscall_num) {
    void *handle = dlopen("./syscall_lib/libsyscall_names.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Error: %s\n", dlerror());
        return NULL;
    }

    // Get the address of the callname function from the library
    const char *(*callname)(long) = dlsym(handle, "callname");
    if (!callname) {
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return NULL;
    }

    // Call the callname function to get the syscall name
    const char *syscall_name = callname(syscall_num);

    // Close the library handle
    dlclose(handle);

    return syscall_name;
}

void print_server_syscalls(pid_t child_pid) {
    int status;
    struct user_regs_struct regs;

    // Attach to the server process
    ptrace(PTRACE_ATTACH, child_pid, NULL, NULL);
    waitpid(child_pid, &status, 0);

    // Loop until the server process stops
    while (WIFSTOPPED(status)) {
        // Get the current registers of the server process
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

   
        if (WSTOPSIG(status) == SIGTRAP) {
            // Get the system call number from the registers
            long syscall_num = regs.orig_rax;

            // Use the get_syscall_name function to get the syscall name
            const char *syscall_name = get_syscall_name(syscall_num);
            if (syscall_name) {
                printf("Syscall: %s\n", syscall_name);
                // Add more logic to print syscall parameters if needed
            }
        }

        // Resume the server process to continue execution
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        waitpid(child_pid, &status, 0); // Wait for the next event
    }

    // Detach from the server process after finishing tracing
    ptrace(PTRACE_DETACH, child_pid, NULL, NULL);
}

void extract_syscall_params(struct user_regs_struct *regs) {
     long syscall_num = regs->orig_rax; // Get the system call number from registers
    switch (regs->orig_rax) {
        case __NR_open:
            printf("Open syscall parameters:\n");
            printf("  File Path: %s\n", (char *)regs->rsi);
            printf("  Flags: %lld\n", regs->rdx);
            break;
        case __NR_read:
            printf("Read syscall parameters:\n");
            printf("  File Descriptor: %lld\n", regs->rdi);
            printf("  Buffer Address: %p\n", (void *)regs->rsi);
            printf("  Buffer Size: %lld\n", regs->rdx);
            break;
        case __NR_write:
            printf("Write syscall parameters:\n");
            printf("  File Descriptor: %lld\n", regs->rdi);
            printf("  Buffer Address: %p\n", (void *)regs->rsi);
            printf("  Buffer Size: %lld\n", regs->rdx);
            break;
        default:
        //none 
            break;
    }
}

void print_full_request(pid_t child_pid) {
    //request_buffer supposed to be where the client's request is stored
    long addr = (long)&request_buffer;

    char buffer[MAX_BUFFER_SIZE];
    struct iovec local[1];
    struct iovec remote[1];
    ssize_t bytes_read;

    // Set up local and remote memory buffers for reading
    local[0].iov_base = buffer;
    local[0].iov_len = sizeof(buffer);
    remote[0].iov_base = (void *)addr;
    remote[0].iov_len = sizeof(buffer);

    // Read the memory buffer using process_vm_readv
    bytes_read = process_vm_readv(child_pid, local, 1, remote, 1, 0);
    if (bytes_read > 0) {
        printf("Full Request from Client:\n%s\n", buffer);
    } else {
        printf("Failed to read the full request.\n");
    }
}

void handle_login(pid_t child_pid) {
    int wait_status;
    int event_type;

    // Enter a loop to continuously monitor the child process
    while (1) {
        // Wait for the child process to stop
        waitpid(child_pid, &wait_status, 0);

        // Check if the child process has exited or terminated
        if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
            // If the child process has exited or terminated, break out of the loop
            break;
        }

        // Get the type of event that caused the child process to stop
        event_type = WSTOPSIG(wait_status);
        switch (event_type) {
            case SIGTRAP:
                // Handle syscall events
                handle_syscall_event(child_pid);
                break;
            default:
                // Resume the child process 
                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                break;
        }
    }
}

void handle_syscall_event(pid_t child_pid) {
    struct user_regs_struct regs;

    // Get the registers of the child process
    if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
        perror("ptrace getregs failed");
        return;
    }

    // Get the system call number from the registers
    long syscall_num = regs.orig_rax;

    // Check if the syscall is relevant to user login
    switch (syscall_num) {
        case __NR_getuid:
            // This syscall gets the real user ID of the calling process
            printf("User with UID %lld is attempting to login.\n", regs.rax);
            break;
        case __NR_geteuid:
            // This syscall gets the effective user ID of the calling process
            printf("User with effective UID %lld is attempting to login.\n", regs.rax);
            break;
        default:
            break;
    }

    // Resume the child process to continue syscall execution
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
}

void event_handling_loop(pid_t child_pid) {
    int wait_status;
    int event_type;

    // Enter a loop to continuously monitor the child process
    while (1) {
        // Wait for the child process to stop
        waitpid(child_pid, &wait_status, 0);

        // Check if the child process has exited or terminated
        if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
            // If the child process has exited or terminated, break out of the loop
            break;
        }

        // Get the type of event that caused the child process to stop
        event_type = WSTOPSIG(wait_status);
        switch (event_type) {
            case SIGTRAP:
                // Handle syscall events
                handle_syscall_event(child_pid);
                break;
            default:
                // Resume the child process to continue execution
                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                break;
        }
    }
}

int main(int argc, char *argv[]) {
    // Check if the correct number of command-line arguments is provided
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <child_pid>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Convert the provided child process ID argument to an integer
    pid_t child_pid = atoi(argv[1]);
    if (child_pid <= 0) {
        fprintf(stderr, "Invalid child PID\n");
        return EXIT_FAILURE;
    }

    // Start event handling loop for tracing and monitoring the child process
    event_handling_loop(child_pid);

    // Print system calls made by the server during the process
    print_server_syscalls(child_pid);


    return EXIT_SUCCESS;
}
