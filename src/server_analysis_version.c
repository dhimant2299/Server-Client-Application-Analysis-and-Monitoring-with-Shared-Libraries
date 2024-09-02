#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <fcntl.h>


#define MAX_BUFFER_SIZE 1024
void *handle = NULL;

void cleanup() {
 if (handle) {
        dlclose(handle);
    }
}

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

void extract_syscall_params(struct user_regs_struct *regs) {
    long syscall_num = regs->orig_rax; // Get the syscall number

    // Switch based on the syscall number to extract parameters
    switch (syscall_num) {
        case __NR_open: {
            long flags = regs->rdx; // Flags are typically stored in rdx for x86-64
            const char *path = (const char *)regs->rsi; // Path is usually in rsi
            // Print or process extracted parameters
            printf("Open syscall parameters:\n");
            printf("Flags: %ld\n", flags);
            printf("Path: %s\n", path);
            break;
        }
        case __NR_read: {
            int fd = (int)regs->rdi; // File descriptor is in rdi
            void *buf = (void *)regs->rsi; // Buffer address is in rsi
            size_t count = (size_t)regs->rdx; // Count is in rdx
            // Print or process extracted parameters
            printf("Read syscall parameters:\n");
            printf("File descriptor: %d\n", fd);
            printf("Buffer address: %p\n", buf);
            printf("Count: %zu\n", count);
            break;
        }
        default:

            break;
    }
}

void handle_file_actions(pid_t child_pid) {
    int status;
    waitpid(child_pid, &status, 0); // Wait for the child process to stop

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        // Child process exited or terminated, handle accordingly
        printf("Child process exited or terminated.\n");
        return;
    }

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs); // Get the registers of the child process

    long syscall_num = regs.orig_rax; // Get the syscall number

    // Handle specific syscalls related to file actions
    switch (syscall_num) {
        case __NR_open: {
            const char *path = (const char *)regs.rdi; // Path is in rdi register
            int flags = regs.rsi; // Flags are in rsi register
            int fd = regs.rax; // File descriptor is returned in rax register

            // Check if the open syscall is for file upload
            if (flags & O_CREAT) {
                printf("File upload detected:\n");
                printf("Path: %s\n", path);
                printf("File descriptor: %d\n", fd);
            }
            break;
        }

        default:
            // none
            break;
    }

    // Resume the child process to continue execution
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
}

void handle_syscall_event(pid_t child_pid) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
        perror("ptrace getregs failed");
        return;
    }

    long syscall_num = regs.orig_rax; // Get the system call number

    // Print or process the syscall information as needed
    printf("Syscall number: %ld\n", syscall_num);

    // Resume the child process to continue syscall execution
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
}


void event_handling_loop(pid_t child_pid) {
    int wait_status;
    int event_type;

    while (1) {
        waitpid(child_pid, &wait_status, 0); // Wait for the child process to stop

        if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
            // Child process exited or terminated, exit the loop
            break;
        }

        event_type = WSTOPSIG(wait_status); // Get the signal that caused the child to stop
        switch (event_type) {
            case SIGTRAP:
                // Handle syscall event
                 handle_syscall_event(child_pid);
                break;
            default:
                break;
        }

        // Resume the child process to continue execution
        ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
    }
}

// Function to print system calls made by the server
void print_server_syscalls(pid_t child_pid) {
    int status;
    struct user_regs_struct regs;

    ptrace(PTRACE_ATTACH, child_pid, NULL, NULL);
    waitpid(child_pid, &status, 0);

    while (WIFSTOPPED(status)) {
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        if (WSTOPSIG(status) == SIGTRAP) {
            const char *syscall_name = get_syscall_name(regs.orig_rax);
            printf("Syscall: %s\n", syscall_name);
        }
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        waitpid(child_pid, &status, 0);
    }

    ptrace(PTRACE_DETACH, child_pid, NULL, NULL);
}


// Function to handle user login attempts and failures
void handle_login(pid_t child_pid) {
    int wait_status;
    int event_type;

    while (1) {
        waitpid(child_pid, &wait_status, 0);

        if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
            break;
        }

        event_type = WSTOPSIG(wait_status);
        switch (event_type) {
            case SIGTRAP:
                handle_syscall_event(child_pid);
                break;
            default:
                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                break;
        }
    }
}

int set_tracing_options(pid_t child_pid) {
    long ptrace_ret;

    ptrace_ret = ptrace(PTRACE_ATTACH, child_pid, 0, 0);
    if (ptrace_ret == -1) {
        perror("ptrace attach failed");
        return -1;
    }
    int wait_status;
    waitpid(child_pid, &wait_status, 0);

    ptrace_ret = ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC);
    if (ptrace_ret == -1) {
        perror("ptrace setoptions failed");
        ptrace(PTRACE_DETACH, child_pid, 0, 0);
        return -1;
    }

    return 0;
}

// Main function
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
 
    // Set tracing options and start event handling loop
    if (set_tracing_options(child_pid) == -1) {
        fprintf(stderr, "Failed to set tracing options\n");
        return EXIT_FAILURE;
    }

    // Start event handling loop
    event_handling_loop(child_pid);
    print_server_syscalls(child_pid);

    return EXIT_SUCCESS;
}
