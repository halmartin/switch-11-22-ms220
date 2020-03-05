/*
 *  BIRD -- Event log
 *
 *  (c) 2014 Cisco Systems, Inc.
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

#include <stdio.h>
#include <nest/bird.h>
#include <conf/conf.h>
#include <lib/birdlib.h>
#include <lib/eventlog.h>
#include <lib/string.h>
#include <errno.h>

void log_event(const char* type, const char* fmt, ...)
{
    if (!config->eventlog_filename)
        return;

    FILE* f = fopen(config->eventlog_filename, "w");
    if (!f) {
        log_msg(L_ERR "Unable to open event log file \"%s\", error %d", config->eventlog_filename, errno);
        return;
    }

    buffer buf;
    LOG_BUFFER_INIT(buf);

    va_list args;
    va_start(args, fmt);
    buffer_vprint(&buf, fmt, args);
    va_end(args);

    fprintf(f, "%s \"%s\" \"\"", type, buf.start);
    fclose(f);
}
