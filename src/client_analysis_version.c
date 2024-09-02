#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <errno.h>

#define MAX_BUFFER_SIZE 1024

// Function to retrieve the name of a syscall using libsyscall_names.so
typedef const char *(*callname_t)(long);
void *handle = NULL;

void cleanup() {
    if (handle) {
        dlclose(handle);
    }
}
   
const char *get_syscall_name(long syscall_num) {
    if (!handle) {
        handle = dlopen("./syscall_lib/libsyscall_names.so", RTLD_LAZY);
        if (!handle) {
            fprintf(stderr, "Error: %s\n", dlerror());
            exit(EXIT_FAILURE);
        }
        atexit(cleanup);
    }
    callname_t callname = (callname_t)dlsym(handle, "callname");
    if (!callname) {
        fprintf(stderr, "Error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    return callname(syscall_num);
}

// Function to extract parameters of relevant syscalls
void extract_syscall_params(struct user_regs_struct *regs) {
    long syscall_num = regs->orig_rax;
    switch (syscall_num) {
        case __NR_open:
            {
        // Extract parameters for open syscall
        unsigned long arg1 = regs->rdi; // File path
        int flags = regs->rsi; // Flags
        int mode = regs->rdx; // Mode
        printf("Open syscall - Path: %s, Flags: %d, Mode: %d\n", (char *)arg1, flags, mode);
    }
            break;
        case __NR_write:
        {
        // Extract parameters for write syscall
        int fd = regs->rdi; // File descriptor
        unsigned long buf = regs->rsi; // Buffer address
        size_t count = regs->rdx; // Number of bytes to write
        printf("Write syscall - FD: %d, Buffer: %p, Count: %zu\n", fd, (void *)buf, count);
    }
            break;
        default:
            break;
    }
}

// Function to handle file uploads and failures
void handle_file_actions(pid_t child_pid) {
    int wait_status;
    int event_type;

    while (1) {
        if (waitpid(child_pid, &wait_status, 0) == -1) {
            perror("waitpid failed");
            return;
        }

        if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
            break;
        }

        event_type = WSTOPSIG(wait_status);
        switch (event_type) {
            case SIGTRAP:
                // Handle file operations here
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
                    perror("ptrace getregs failed");
                    return;
                }

                long syscall_num = regs.orig_rax;

                // Check for relevant syscalls
                switch (syscall_num) {
                    case __NR_open:
                        {
                            unsigned long arg1 = regs.rdi; // File path
                            if (arg1) {
                                printf("File Opened: %s\n", (char *)arg1);
                            } else {
                                printf("Open syscall failed\n");
                            }
                        }
                        break;
                    case __NR_write:
                        {
                            int bytes_written = regs.rax; // Bytes written
                            if (bytes_written > 0) {
                                printf("Write Successful - Bytes Written: %d\n", bytes_written);
                            } else {
                                printf("Write Failed\n");
                            }
                        }
                        break;
                    default:
                        break;
                }

                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                break;
            default:
                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                break;
        }
    }
}


void handle_syscall_event(pid_t child_pid) {
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
        perror("ptrace getregs failed");
        return;
    }

    long syscall_num = regs.orig_rax;

    // Check if it's a relevant login-related syscall
    switch (syscall_num) {
        case __NR_getuid:
            printf("User with UID %lld is attempting to login.\n", regs.rax);
            break;
        case __NR_geteuid:
            printf("User with effective UID %lld is attempting to login.\n", regs.rax);
            break;

        default:
            break;
    }
    
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
}
 
void event_handling_loop(pid_t child_pid) {
    int wait_status;
    int event_type;

    while (1) {
        waitpid(child_pid, &wait_status, 0);

        if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
            break;  // Exit the loop if the child process exits 
        }

        event_type = WSTOPSIG(wait_status);
        switch (event_type) {
            case SIGTRAP:
                // Handle the syscall event
                handle_syscall_event(child_pid);
                break;
            case SIGSTOP:
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

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <child_pid>\n", argv[0]);
        return EXIT_FAILURE;
    }

    pid_t child_pid = atoi(argv[1]);
    if (child_pid <= 0) {
        fprintf(stderr, "Invalid child PID\n");
        return EXIT_FAILURE;
    }
    // Set tracing options for the child process
    if (set_tracing_options(child_pid) == -1) {
        fprintf(stderr, "Failed to set tracing options\n");
        return EXIT_FAILURE;
    }
    // Attach to the child process for tracing
    if (ptrace(PTRACE_ATTACH, child_pid, 0, 0) == -1) {
        perror("ptrace attach failed");
        return EXIT_FAILURE;
    }

    int wait_status;
    waitpid(child_pid, &wait_status, 0);

    // Main tracing loop
    while (1) {
        if (waitpid(child_pid, &wait_status, 0) == -1) {
            perror("waitpid failed");
            ptrace(PTRACE_DETACH, child_pid, 0, 0);
            return EXIT_FAILURE;
        }

        if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
            break;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
            perror("ptrace getregs failed");
            ptrace(PTRACE_DETACH, child_pid, 0, 0);
            return EXIT_FAILURE;
        }

        long syscall_num = regs.orig_rax;

        // Get the name of the syscall
        const char *syscall_name = get_syscall_name(syscall_num);
        if (!syscall_name) {
            fprintf(stderr, "Error: Unknown syscall %ld\n", syscall_num);
            ptrace(PTRACE_DETACH, child_pid, 0, 0);
            return EXIT_FAILURE;
        }

        // Print the syscall name
        printf("Syscall: %s\n", syscall_name);

        // Extract parameters of relevant syscalls
        extract_syscall_params(&regs);

        // Continue tracing the child process
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1) {
            perror("ptrace syscall failed");
            ptrace(PTRACE_DETACH, child_pid, 0, 0);
            return EXIT_FAILURE;
        }
    }

    // Handle file uploads and failures
    handle_file_actions(child_pid);

    // Detach from the child process
    if (ptrace(PTRACE_DETACH, child_pid, 0, 0) == -1) {
        perror("ptrace detach failed");
        return EXIT_FAILURE;
    }
    // Start the event handling loop
    event_handling_loop(child_pid);

    return EXIT_SUCCESS;
}
