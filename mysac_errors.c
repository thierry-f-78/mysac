/*
 * Copyright (c) 2009 Thierry FOURNIER
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License.
 *
 */

#include "mysac.h"

const char *mysac_errors[]  = {
	[0]                      = "no error",
	[MYERR_PROTOCOL_ERROR]   = "mysql protocol error",
	[MYERR_BUFFER_OVERSIZE]  = "buffer oversize",
	[MYERR_PACKET_CORRUPT]   = "packet corrupted",
	[MYERR_WANT_READ]        = "mysac need to read data on socket",
	[MYERR_WANT_WRITE]       = "mysac need to write data on socket",
	[MYERR_UNKNOWN_ERROR]    = "unknown error",
	[MYERR_MYSQL_ERROR]      = "mysql server return an error",
	[MYERR_SERVER_LOST]      = "server network connexion is break",
	[MYERR_BAD_PORT]         = "bad port number",
	[MYERR_RESOLV_HOST]      = "can not resolve host name",
	[MYERR_SYSTEM]           = "system error (see errno)",
	[MYERR_CANT_CONNECT]     = "can not connect to host",
	[MYERR_BUFFER_TOO_SMALL] = "the buffer can not contain request",
	[MYERR_UNEXPECT_R_STATE] = "Unexpected state when reading data",
	[MYERR_STRFIELD_CORRUPT] = "Mysql string mode field corrupt",
	[MYERR_BINFIELD_CORRUPT] = "Mysql binary mode field corrupt"
};

