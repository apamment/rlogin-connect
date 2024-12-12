#include <termios.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include "Rlogin.h"

void print_help() {
    printf("Required Arguments:\n");
    printf(" -H HOSTNAME\n");
    printf(" -P PORT\n");
    printf(" -R REMOTE USERNAME\n");
    printf("Optional Arguments:\n");
    printf(" -T TERMTYPE\n");
    printf(" -L LOCAL USERNAME (PASSWORD)\n");
    printf(" -6 USE IPv6\n");
}

int main(int argc, char **argv) {
    std::string host = "";
    int port = -1;
    std::string luser = "";
    std::string ruser = "";
    std::string termt = "";
    bool ip6 = false;

    for (int i = 1; i < argc; i++) {
        if (strcasecmp(argv[i], "-H") == 0 && i < argc - 1) {
            host = std::string(argv[++i]);
        } else if (strcasecmp(argv[i], "-P") == 0 && i < argc - 1) {
            port = strtol(argv[++i], NULL, 10);
        } else if (strcasecmp(argv[i], "-L") == 0 && i < argc - 1) {
            luser = std::string(argv[++i]);
        } else if (strcasecmp(argv[i], "-R") == 0 && i < argc - 1) {
            ruser = std::string(argv[++i]);
        } else if (strcasecmp(argv[i], "-T") == 0 && i < argc - 1) {
            termt = std::string(argv[++i]);
        } else if (strcasecmp(argv[i], "-6") == 0) {
            ip6 = true;
        } else {
            print_help();
            return -1;
        }
    }

    if (ruser == "" || host == "" || port == -1) {
        print_help();
        return -1;
    }
    struct termios old_t;
    struct termios new_t;
    if (isatty(STDOUT_FILENO)) {
        tcgetattr(STDOUT_FILENO, &old_t);
        new_t = old_t;
        cfmakeraw(&new_t);
        tcsetattr(STDOUT_FILENO, TCSANOW, &new_t);
    }

    bool ret = Rlogin::session(host, port, luser, ruser, termt, ip6);

    if (isatty(STDOUT_FILENO)) {
        tcsetattr(STDOUT_FILENO, TCSANOW, &old_t);
    }
    if (ret) {
        return 0;
    }
    return -1;
}