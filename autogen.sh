#!/bin/sh

# journal-triggerd - Copyright (C) 2013 Olivier Brunel
#
# autogen.sh
# Copyright (C) 2013 Olivier Brunel <i.am.jack.mail@gmail.com>
# Copyright (C) 2003-2012 Sebastien Helleu <flashcode@flashtux.org>
# Copyright (C) 2005 Julien Louis <ptitlouis@sysif.net>
# Copyright (C) 2005-2006 Emmanuel Bouthenot <kolter@openics.org>
#
# This file is part of journal-triggerd.
#
# journal-triggerd is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# journal-triggerd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# journal-triggerd. If not, see http://www.gnu.org/licenses/

# Based on autogen.sh from WeeChat, http://weechat.org

LOG=autogen.log

abort()
{
    echo "An error occured, the output below can be found in $LOG"
    echo "-------"
    cat $LOG
    exit 1
}

run()
{
    echo -n "Running \"$@\" ... "
    echo "$ $@" >>$LOG
    eval $@ >>$LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "OK"
    else
        echo "FAILED"
        abort
    fi
}

if [ -e $LOG ]; then
    rm "$LOG"
fi

run "mkdir build-aux"
run "aclocal -I m4"
run "autoheader"
run "autoconf"
run "automake --add-missing --copy"

echo "done; Full log available in $LOG"
