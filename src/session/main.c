/*
 * D-Bus Session Initiator Main Entry
 */

#include <c-stdaux.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "util/error.h"

enum {
        _MAIN_SUCCESS,
        MAIN_EXIT,
        MAIN_FAILED,
};

const int ERROR_SELF = 127;
const int ERROR_SIGNAL = 128;

static const char* main_config_file = NULL;
static const char* main_dbus_broker = NULL;
static const char* main_dbus_daemon = NULL;
static char** main_program_argv = NULL;

static void help(void) {
        printf("%s [GLOBALS...] <PROGRAM> ...\n\n"
               "Linux D-Bus Message Session Launcher\n\n"
               "  -h --help                     Show this help\n"
               "     --version                  Show package version\n"
               "     --config-file PATH         Path to the config-file to use for the message broker\n"
               "     --dbus-broker BINARY       Name or path of the dbus-broker launcher executable\n"
               "     --dbus-daemon BINARY       Name or path of the dbus-daemon executable\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_CONFIG_FILE,
                ARG_DBUS_BROKER,
                ARG_DBUS_DAEMON,
        };
        static const struct option options[] = {
                { "help",               no_argument,            NULL,   'h'                     },
                { "version",            no_argument,            NULL,   ARG_VERSION             },
                { "config-file",        required_argument,      NULL,   ARG_CONFIG_FILE         },
                { "dbus-broker",        optional_argument,      NULL,   ARG_DBUS_BROKER         },
                { "dbus-daemon",        optional_argument,      NULL,   ARG_DBUS_DAEMON         },
                {}
        };
        unsigned char mode = 0;
        int c;

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        help();
                        return MAIN_EXIT;
                case ARG_VERSION:
                        printf("dbus-broker-session %d\n", PACKAGE_VERSION);
                        return MAIN_EXIT;
                case ARG_CONFIG_FILE:
                        main_config_file = optarg;
                        break;
                case ARG_DBUS_BROKER:
                        mode |= 1;
                        if (!optarg && argv[optind] && argv[optind][0] != '-') {
                                main_dbus_broker = argv[optind++];
                        } else {
                                main_dbus_broker = "dbus-broker-launch";
                        }
                        break;
                case ARG_DBUS_DAEMON:
                        mode |= 2;
                        if (!optarg && argv[optind] && argv[optind][0] != '-') {
                                main_dbus_daemon = argv[optind++];
                        } else {
                                main_dbus_daemon = "dbus-daemon";
                        }
                        break;
                case '?':
                        /* getopt_long() prints warning */
                        return MAIN_FAILED;

                default:
                        return error_origin(-EINVAL);
                }
        }

        if (optind == argc) {
                fprintf(stderr, "%s: missing program name\n", program_invocation_name);
                return MAIN_FAILED;
        }

        if (mode > 2) {
                fprintf(stderr, "%s: can not specify --dbus-broker and --dbus-daemon at the same time\n", program_invocation_name);
                return MAIN_FAILED;
        }

        main_program_argv = &argv[optind];

        return 0;
}

static int create_dbus_broker_listener(const char* address) {
        int r, listener_fd;
        struct sockaddr_un addr;
        socklen_t addr_len;
        struct stat statbuf;

        c_assert(address);
        if (stat(address, &statbuf) == 0) {
                unlink(address);
        }

        listener_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (listener_fd < 0) {
                return error_origin(-errno);
        }

        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, address, sizeof(addr.sun_path) - 1);
        addr_len = sizeof(addr);

        r = bind(listener_fd, (struct sockaddr*)&addr, addr_len);
        if (r < 0) {
                close(listener_fd);
                return error_origin(-errno);
        }

        r = listen(listener_fd, 1);
        if (r < 0) {
                close(listener_fd);
                return error_origin(-errno);
        }
        return listener_fd;
}

static int spawn_dbus_broker(char **bus_address) {
        int r, listener_fd;
        pid_t pid, child_pid;
        const char* address_template = "/tmp/dbus-XXXXXX";
        char *address = strdup(address_template);
        char str_child_pid[C_DECIMAL_MAX(pid_t) + 1];
        char str_address[11 + strlen(address_template) + 1];
        const char * const argv[] = {
                main_dbus_broker ? main_dbus_broker : "dbus-broker-launch",
                "--audit",
                "--scope=user",
                /* note that this needs to be the last argument to work */
                main_config_file ? "--config-file" : NULL,
                main_config_file ? main_config_file : NULL,
                NULL
        };
        c_assert(address);
        r = mkstemp(address);
        if (r < 0) {
                return error_origin(-errno);
        }
        *bus_address = address;
        listener_fd = create_dbus_broker_listener(address);
        if (listener_fd < 0) {
                return error_origin(-errno);
        }

        pid = fork();
        if (pid < 0) {
                return error_origin(-errno);
        }
        if (!pid) {
                r = prctl(PR_SET_PDEATHSIG, SIGTERM);
                if (r < 0) {
                        r = error_origin(-errno);
                        _exit(EXIT_FAILURE);
                }
                child_pid = getpid();
                r = snprintf(str_child_pid, sizeof(str_child_pid), "%d", child_pid);
                c_assert(r < (ssize_t)sizeof(str_child_pid));
                r = setenv("LISTEN_PID", str_child_pid, 1);
                if (r < 0) {
                        r = error_origin(-errno);
                        _exit(EXIT_FAILURE);
                }
                r = setenv("LISTEN_FDS", "1", 1);
                if (r < 0) {
                        r = error_origin(-errno);
                        _exit(EXIT_FAILURE);
                }
                r = dup2(listener_fd, 3);
                if (r < 0) {
                        r = error_origin(-errno);
                        _exit(EXIT_FAILURE);
                }
                execvpe(argv[0], (char *const *)argv, environ);
                error_origin(-errno);
                _exit(EXIT_FAILURE);
        }

        r = snprintf(str_address, sizeof(str_address), "unix:path=%s", address);
        c_assert(r < (ssize_t)sizeof(str_address));
        r = setenv("DBUS_SESSION_BUS_ADDRESS", str_address, 1);
        if (r < 0) {
                r = error_origin(-errno);
                return r;
        }

        return pid;
}

static int read_dbus_daemon_address(int fd, char **out_address) {
        char buffer[1024];
        ssize_t r;
        char *address;

        r = read(fd, buffer, sizeof(buffer) - 1);
        if (r < 0) {
                return error_origin(-errno);
        }
        buffer[r] = '\0';

        address = strchr(buffer, '\n');
        if (!address) {
                return error_origin(-EIO);
        }
        *address = '\0';

        *out_address = strdup(buffer);
        return 0;
}

static int spawn_dbus_daemon(void) {
        int r;

        int fds[2];
        _c_cleanup_(c_closep) int read_fd = -1, write_fd = -1;
        char str_fd_write[C_DECIMAL_MAX(int) + 1];
        _c_cleanup_(c_freep) char *session_bus_address = NULL;
        pid_t pid;
        const char * const argv[] = {
                main_dbus_daemon ? main_dbus_daemon : "dbus-daemon",
                "--nofork",
                "--print-address",
                str_fd_write,
                /* note that this needs to be the last argument to work */
                main_config_file ? "--config-file" : "--session",
                main_config_file ? main_config_file : NULL,
                NULL
        };


        r = pipe2(fds, 0);

        if (r < 0) {
                return error_origin(-errno);
        }
        read_fd = fds[0];
        write_fd = fds[1];

        r = snprintf(str_fd_write, sizeof(str_fd_write), "%d", write_fd);
        c_assert(r < (ssize_t)sizeof(str_fd_write));

        pid = fork();
        if (pid < 0) {
                return error_origin(-errno);
        }
        if (!pid) {
                r = prctl(PR_SET_PDEATHSIG, SIGTERM);
                if (r < 0) {
                        r = error_origin(-errno);
                        _exit(EXIT_FAILURE);
                }
                execvpe(argv[0], (char *const *)argv, environ);
                error_origin(-errno);
                _exit(EXIT_FAILURE);
        }
        r = read_dbus_daemon_address(read_fd, &session_bus_address);
        if (r < 0) {
                return r;
        }
        c_assert(session_bus_address);
        r = setenv("DBUS_SESSION_BUS_ADDRESS", session_bus_address, 1);
        if (r < 0) {
                r = error_origin(-errno);
                return r;
        }
        return pid;
}

static int spawn_control(void) {
        int r;
        pid_t pid;

        pid = fork();
        if (pid < 0) {
                return error_origin(-errno);
        }
        if (!pid) {
                c_assert(main_program_argv && main_program_argv[0]);
                r = prctl(PR_SET_PDEATHSIG, SIGTERM);
                if (r < 0) {
                        r = error_origin(-errno);
                        _exit(EXIT_FAILURE);
                }
                execvpe(main_program_argv[0], (char *const *)main_program_argv, environ);
                error_origin(-errno);
                _exit(EXIT_FAILURE);
        }
        return pid;
}

static int wait_for_session_end(pid_t bus_pid, pid_t control_pid) {
        int status, r = 0;

        r = wait(&status);
        if (r < 0) {
                r = error_origin(-errno);
                return r;
        }

        if (r == bus_pid) {
                if (WIFEXITED(status) != 0) {
                        fprintf(stderr, "message broker exited unexpectedly with %d\n", WEXITSTATUS(status));
                } else if (WIFSIGNALED(status) != 0) {
                        fprintf(stderr, "message broker received signal %d\n", WTERMSIG(status));
                } else {
                        fprintf(stderr, "message broker terminated unexpectedly\n");
                }
        } else if (r == control_pid) {
                if (WIFEXITED(status) != 0) {
                        return WEXITSTATUS(status);
                } else if (WIFSIGNALED(status) != 0) {
                        return ERROR_SIGNAL + WTERMSIG(status);
                } else {
                        fprintf(stderr, "session controller was terminated unexpectedly\n");
                        return ERROR_SELF;
                }
        }

        return 0;
}

static void free_bus_addressp(char **address) {
        if (*address) {
                unlink(*address);
                free(*address);
                *address = NULL;
        }
}

static void free_child_processp(pid_t *pid) {
        if (*pid > 0) {
                kill(*pid, SIGTERM);
                *pid = -1;
        }
}

const char* const dbus_session_variable_names[] = {
        "DBUS_SESSION_BUS_PID",
        "DBUS_SESSION_BUS_WINDOWID",
        "DBUS_STARTER_ADDRESS",
        "DBUS_STARTER_BUS_TYPE"
};
int main(int argc, char **argv) {
        int r;
        _c_cleanup_(free_child_processp) int child, control;
        _c_cleanup_(free_bus_addressp) char *bus_address = NULL;

        for (size_t i = 0; i < (sizeof(dbus_session_variable_names) / sizeof(char*)); i++) {
                unsetenv(dbus_session_variable_names[i]);
        }

        r = parse_argv(argc, argv);
        if (r)
                goto exit;

        if (main_dbus_daemon && !main_dbus_broker) {
                child = spawn_dbus_daemon();
        } else {
                child = spawn_dbus_broker(&bus_address);
        }
        if (child < 0)
                goto exit;
        control = spawn_control();
        if (control < 0)
                goto exit;

        r = wait_for_session_end(child, control);
        if (r)
                return r;

exit:
        r = error_trace(r);
        return (r == 0 || r == MAIN_EXIT) ? 0 : ERROR_SELF;
}
