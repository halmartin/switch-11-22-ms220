/*
 *  Click socket proxy -- API calls
 *
 *  Copyright (C) 2014 Cisco Systems, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <netinet/in.h>
#include <string.h>
#include <exception>
#include <errno.h>
#include "sockproxy.h"
#include "sockproxy_int.hh"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

SOCKPROXY_USING_DECLS

// We don't want ANY exceptions bubbling up into the calling code, which
// is likely C code that doesn't understand C++ exceptions.
// We shouldn't see any exceptions that aren't derived from std::exception,
// but I've added a (...) case just to be safe.
#define CATCH_EXCEPTIONS(x) \
    try { \
        return (x); \
    } catch (const std::bad_alloc&) { \
        errno = ENOMEM; \
        return -1; \
    } catch (const std::exception& ex) { \
        errno = EIO; \
        critical("%s exception: %s", __func__, ex.what());       \
        return -1; \
    } catch (...) { \
        errno = EIO; \
        critical("%s unknown exception", __func__);      \
        return -1; \
    }

csp_debug_fn SOCKPROXY_NAME(g_csp_debug_fn) = NULL;

void
CSP_register_debug(csp_debug_fn fn) throw()
{
    g_csp_debug_fn = fn;
}

int
CSP_set_config(const sockproxy_cfg* cfg) throw()
{
    CATCH_EXCEPTIONS(_csp_set_config(cfg));
}

int
CSP_clear_config(void) throw()
{
    CATCH_EXCEPTIONS(_csp_clear_config());
}

int
CSP_socket(int domain, int type, int protocol) throw()
{
    CATCH_EXCEPTIONS(_csp_socket(domain, type, protocol));
}

int
CSP_bind(int sockfd, struct sockaddr* addr, socklen_t addrlen) throw()
{
    CATCH_EXCEPTIONS(_csp_bind(sockfd, addr, addrlen));
}

int
CSP_getsockname(int sockfd, struct sockaddr* addr, socklen_t* addrlen) throw()
{
    CATCH_EXCEPTIONS(_csp_getsockname(sockfd, addr, addrlen));
}

ssize_t
CSP_sendmsg(int sockfd, const struct msghdr* msg, int flags) throw()
{
    CATCH_EXCEPTIONS(_csp_sendmsg(sockfd, msg, flags));
}


ssize_t
CSP_send(int sockfd, const void* buf, size_t len, int flags) throw()
{
    CATCH_EXCEPTIONS(_csp_sendto(sockfd, buf, len, flags, NULL, 0));
}


ssize_t
CSP_sendto(int sockfd, const void* buf, size_t len, int flags,
           const struct sockaddr* dest_addr, socklen_t addrlen) throw()
{
    CATCH_EXCEPTIONS(_csp_sendto(sockfd, buf, len, flags, dest_addr, addrlen));
}

ssize_t
CSP_recvmsg(int sockfd, struct msghdr* msg, int flags) throw()
{
    CATCH_EXCEPTIONS(_csp_recvmsg(sockfd, msg, flags));
}

ssize_t
CSP_recvfrom(int sockfd, void* buf, size_t len, int flags,
             struct sockaddr* src_addr, socklen_t* addrlen) throw()
{
    CATCH_EXCEPTIONS(_csp_recvfrom(sockfd, buf, len, flags, src_addr, addrlen));
}


ssize_t
CSP_recv(int sockfd, void* buf, size_t len, int flags) throw()
{
    CATCH_EXCEPTIONS(_csp_recvfrom(sockfd, buf, len, flags, NULL, NULL));
}

int
CSP_close(int fd) throw()
{
    CATCH_EXCEPTIONS(_csp_close(fd));
}

int
CSP_setsockopt(int sockfd, int level, int optname,
               const void *optval, socklen_t optlen) throw()
{
    CATCH_EXCEPTIONS(_csp_setsockopt(sockfd, level, optname, optval, optlen));
}

int
CSP_getsockopt(int sockfd, int level, int optname,
               void *optval, socklen_t* optlen) throw()
{
    CATCH_EXCEPTIONS(_csp_getsockopt(sockfd, level, optname, optval, optlen));
}

int
CSP_select(int nfds, fd_set* read_fds, fd_set* write_fds,
           fd_set* except_fds, struct timeval* timeout) throw()
{
    CATCH_EXCEPTIONS(_csp_select(nfds, read_fds, write_fds, except_fds, timeout));
}

int
CSP_fcntl_int(int fd, int cmd, int optval) throw()
{
    CATCH_EXCEPTIONS(_csp_fcntl_int(fd, cmd, optval));
}

int
CSP_ioctl(int fd, unsigned long int request, void *arg) throw()
{
    CATCH_EXCEPTIONS(_csp_ioctl(fd, request, arg));
}

int
CSP_read(int fd, void* buf, size_t count) throw()
{
    CATCH_EXCEPTIONS(_csp_read(fd, buf, count));
}

int
CSP_write(int fd, const void* buf, size_t count) throw()
{
    CATCH_EXCEPTIONS(_csp_write(fd, buf, count));
}

int
CSP_get_open_sockets(int* fds, socklen_t* count) throw()
{
    CATCH_EXCEPTIONS(_csp_get_open_sockets(fds, count));
}

int
CSP_get_stats(struct sockproxy_stats* stats) throw()
{
    CATCH_EXCEPTIONS(_csp_get_stats(stats));
}

int
CSP_get_socket_stats(int fd, struct sockproxy_socket_stats* stats) throw()
{
    CATCH_EXCEPTIONS(_csp_get_socket_stats(fd, stats));
}

int
CSP_reset_stats(void) throw()
{
    CATCH_EXCEPTIONS(_csp_reset_stats());
}

static int
meraki_shell_quote(const char *in, char *out, size_t size)
{
    char *c = out;
    const char *c2 = in;
    int i = 0;
    *c++ = '\"';
    while (*c2) {
        if ((*c2 == '\'') || (*c2 == '\"')) {
            *c++ = '\\';
        }
        *c++ = *c2++;
        i++;
        if (i >= size) {
            CSP::error("%s: Command too long: failed \"%s\"", __func__, in);
            return -1;
        }
    }
    *c++ = '\"';
    *c = '\0';
    return 0;
}

int
meraki_click_write(const char *clickpath, const char *value) NOEXCEPT
{
    int i, ret;
    struct stat sbuf;
    ret = stat(clickpath, &sbuf);
    if (ret == 0) {
        /* File exists */
        int f = open(clickpath, O_WRONLY | O_TRUNC, 0644);
        if (f < 0) {
            CSP::error("%s: open failed \"%s\", error = %m", __func__, clickpath);
            return -1;
        } else {
            if (write(f, value, strlen(value)) < 0) {
                CSP::error("%s: write failed \"%s\", error = %m", __func__, clickpath);
                ret = -1;
            }
            if (close(f) != 0) {
                CSP::error("%s: close failed \"%s\", error = %m", __func__, clickpath);
            }
        }
    } else {
        /* File does not exist, use click_write utility */
        const char *cname = "/usr/bin/click_write";
        size_t cbufsize = MERAKI_CLICK_COMMAND_SIZE + strlen(cname) + strlen(clickpath) + 3;
        char cbuf[cbufsize];
        i = snprintf(cbuf, cbufsize, "%s %s ", cname, clickpath);
        /* Copy "value" into cbuf, quoting the whole thing and escaping quotes inside */
        if (meraki_shell_quote(value, &cbuf[i], cbufsize - i) != 0) {
            CSP::error("%s: shell quote failed \"%s\"", __func__, clickpath);
            ret = -1;
        } else {
            ret = system(cbuf);
            if (ret != 0) {
                CSP::error("%s: command failed \"%s\", error = %m", __func__, cbuf);
                ret = -1;
            }
        }
    }
    return ret;
}

int
meraki_click_read(char *buf, size_t bufsize, const char *clickpath, const char *value, size_t *bytes_read) NOEXCEPT
{
    int i, ret;
    struct stat sbuf;
    ret = stat(clickpath, &sbuf);
    if (ret == 0) {
        /* File exists */
        int f = open(clickpath, O_RDWR);
        if (f < 0) {
            CSP::error("%s: open failed \"%s\", error = %m", __func__, clickpath);
            return -1;
        } else {
            if (write(f, value, strlen(value)) < 0) {
                CSP::error("%s: write failed \"%s\", error = %m", __func__, clickpath);
                ret = -1;
            } else if ((*bytes_read = read(f, buf, bufsize)) < 0) {
                CSP::error("%s: read failed \"%s\", error = %m", __func__, clickpath);
                ret = -1;
            }
            if (close(f) != 0) {
                CSP::error("%s: close failed \"%s\", error = %m", __func__, clickpath);
            }
        }
    } else {
        ret = 0;
        /* File does not exist, use click_read utility */
        const char *cname = "/usr/bin/click_read";
        size_t cbufsize = MERAKI_CLICK_COMMAND_SIZE + strlen(cname) + strlen(clickpath) + 3;
        char cbuf[cbufsize];
        i = snprintf(cbuf, cbufsize, "%s %s ", cname, clickpath);
        if (i < 0) {
            ret = -1;
            CSP::error("%s: snprintf failed \"%s\"", __func__, clickpath);
        } else if (meraki_shell_quote(value, &cbuf[i], cbufsize - i) != 0) {
            CSP::error("%s: shell quote failed \"%s\"", __func__, clickpath);
            ret = -1;
        } else {
            FILE *fp = popen(cbuf, "r");
            if (!fp) {
                CSP::error("%s: popen failed \"%s\", error = %m", __func__, clickpath);
                return -1;
            } else {
                if ((*bytes_read = fread(buf, sizeof(char), bufsize, fp)) < 0) {
                    CSP::error("%s: read failed \"%s\", error = %m", __func__, clickpath);
                    ret = -1;
                }
                pclose(fp);
            }
        }
    }
    return ret;
}
