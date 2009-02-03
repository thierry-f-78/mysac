#include "mysac.h"

const char *mysac_errors[] ={
	[MYERR_PROTOCOL_ERROR]  = "mysql protocol error",
	[MYERR_BUFFER_OVERSIZE] = "buffer oversize",
	[MYERR_PACKET_CORRUPT]  = "packet corrupted",
	[MYERR_WANT_READ]       = "mysac need to read data on socket",
	[MYERR_WANT_WRITE]      = "mysac need to write data on socket",
	[MYERR_UNKNOWN_ERROR]   = "unknown error",
	[MYERR_MYSQL_ERROR]     = "mysql server return an error",
	[MYERR_SERVER_LOST]     = "server network connexion is break",
	[MYERR_BAD_PORT]        = "bad port number",
	[MYERR_RESOLV_HOST]     = "can not resolve host name",
	[MYERR_SYSTEM]          = "system error (see errno)",
	[MYERR_CANT_CONNECT]    = "can not connect to host"

};

