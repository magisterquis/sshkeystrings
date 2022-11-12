/*
 * sshkeystrings.c
 * Extract strings which might be in an SSH key file
 * By J. Stuart McMurray
 * Created 20221112
 * Last Modified 20221112
 */

#include <sys/mman.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __OpenBSD__
#define MAP_FLAGS MAP_SHARED|MAP_CONCEAL
#else
#define MAP_FLAGS MAP_SHARED
#endif /* #ifdef __OpenBSD__ */

/* Character sets. */
#define START_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"\
        "0123456789+/-"
#define B64_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"\
        "0123456789+/-"

/* Markers which start and end SSH keys. */
#define RSA_BEGIN "-----BEGIN RSA PRIVATE KEY-----\n"
#define RSA_END "-----END RSA PRIVATE KEY-----"
#define OPENSSH_BEGIN "-----BEGIN OPENSSH PRIVATE KEY-----\n"
#define OPENSSH_END "-----END OPENSSH PRIVATE KEY-----"
struct marker {
        char  *line;
        size_t len;
};
struct marker markers[] = {
        {RSA_BEGIN, 32},
        {RSA_END, 29},
        {OPENSSH_BEGIN, 36},
        {OPENSSH_END, 33}};
int markers_len = 4;

void usage(void);
int process(const char *fn);
int is_in_set(const char *set, char c);
void must_write_all(const char *p, size_t len);

/* marker_lines are the four strings which indicate the beginning and end of a
 * key. */
char *marker_lines[]   = {RSA_BEGIN, RSA_END, OPENSSH_BEGIN, OPENSSH_END};
int   marker_lines_len = 4;

int
main(int argc, char **argv)
{
        int i, ret;

        /* Help out the user? */
        if (2 > argc || 0 == strcmp("-h", argv[1])) {
                usage();
                exit(1);
        }

#ifdef __OpenBSD__
        if (-1 == pledge("rpath stdio", ""))
                err(8, "pledge");
        for (i = 1; i < argc; ++i)
                if (-1 == unveil(argv[i], "r"))
                        err(9, "unveil %s", argv[i]);
        if (-1 == unveil(NULL, NULL))
                err(10, "unveil");
#endif /* #ifdef __OpenBSD */

        /* Scrape each file. */
        ret = 1;
        for (i = 1; i < argc; ++i)
                ret |= process(argv[i]);

        return ret;
}

/* usage prints out a help statement. */
void
usage(void)
{
        extern char *__progname;
        fprintf(stderr, "Usage: %s file [file...]]\n", __progname);
        fprintf(stderr, "\n");
        fprintf(stderr, "Prints lines from the given file(s) which might be "
                        "part of SSH private key\n");
        fprintf(stderr, "files.\n");
}

/* process searches for private key strings in the file named fn. */
int
process(const char *fn)
{
        int fd, i, found, oth;
        off_t len;
        void *m;
        char *start, *next, *stop, prev;

        /* Map the file into memory. */
        if (-1 == (fd = open(fn, O_RDONLY, 0))) {
                warn("open(%s)", fn);
                return 1;
        }
        if (-1 == (len = lseek(fd, 0, SEEK_END))) {
                warn("lseek(%s)", fn);
                return 2;
        }
        m = mmap(NULL, (size_t)len, PROT_READ, MAP_FLAGS, fd, 0);
        close(fd);
        if (MAP_FAILED == m) {
                warn("mmap(%s)", fn);
                return 3;
        }
        stop = (char *)m + len;

        /* Search for appropriate strings. */
        prev = '\0';
        for (start = (char *)m; start < stop; start = next, prev = *(start-1)) {
                /* Find the beginning of a string. */
                for (; !is_in_set(START_CHARS, *start) && start < stop;
                                ++start);
                if (start >= stop)
                        break;


                /* If the string is a begin or end, print it and move on. */
                found = 0;
                for (i = 0; '-' == *start && i < markers_len; ++i) {
                        /* Make sure we have enough space left for the
                         * marker. */
                        if (start + markers[i].len >= stop)
                                continue;
                        /* If this is a line, print it and update where we'll
                         * start next. */
                        if (0 == strncmp(markers[i].line, start,
                                                markers[i].len)) {
                                if (0 > printf("%s", markers[i].line))
                                        err(4, "printf");
                                if ('\n' != markers[i].line[markers[i].len-1])
                                        if (0 > printf("\n"))
                                                err(5, "printf");
                                if (EOF == fflush(stdout))
                                        err(6, "fflush");
                                next = start + markers[i].len;
                                found = 1;
                        }
                        if (found)
                                break;
                }
                if (found)
                        continue;

                /* Work out the end of a possible base64 chunk, which must have
                 * been preceded with a newline. */
                if ('\n' != prev) {
                        next = start + 1;
                        continue;
                }
                for (next = start; is_in_set(B64_CHARS, *next) &&
                                next < stop; ++next);
                if (next == start) {/* Not base64. */
                        continue;
                }

                /* We can have at most three characters after the base64, up to
                 * two ='s and one \n. */
                found = oth = 0;
                for (i = 0; i < 3 && next < stop; ++next) {
                        switch (*next) {
                                case '\n': /* Good :) */
                                        ++next;
                                        found = 1;
                                        break;
                                case '=':
                                        break;
                                default:
                                        oth = 1;
                                        break;
                        }
                        if (found || oth) {
                                break;
                        }
                }

                /* If we got a string, print it and move on. */
                if (found) {
                        must_write_all(start, next - start);
                }
        }

        munmap(m, len);
        return 0;
}

/* is_in_set returns nonzero if c is not \0 and is in s. */
int
is_in_set(const char *set, char c)
{
        /* Don't want NULs. */
        if ('\0' == c)
                return 0;

        /* See if the character's in s. */
        return NULL != strchr(set, c);
}

/* must_write_all writes all len bytes at p, or terminates the program. */
void
must_write_all(const char *p, size_t len)
{
        size_t off;
        ssize_t nw;

        for (off = 0; off < len; off += nw)
                if ((nw = write(STDOUT_FILENO, p + off, len - off)) == 0 ||
                                nw == -1)
                        err(7, "write");
}
