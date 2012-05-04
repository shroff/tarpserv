/*
Copyright (C) 2012 Abhishek Shroff

This file is a part of tarpserv.

tarpserv is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

tarpserv is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef __TARP_LTA_H
#define __TARP_LTA_H

#include "packets.h"

char* tarp_create_ticket(u_char *, ip_address *, char *);

#endif
