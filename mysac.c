#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <mysql/mysql.h>

#include "mysac.h"

static uint32_t from_my_16(char *m) {
	return ( (unsigned char)m[1] << 8 ) |
	         (unsigned char)m[0];
}
static uint32_t from_my_24(char *m) {
	return ( (unsigned char)m[2] << 16 ) |
	       ( (unsigned char)m[1] << 8 ) |
	         (unsigned char)m[0];
}
static uint32_t from_my_32(char *m) {
	return ( (unsigned char)m[3] << 24 ) |
	       ( (unsigned char)m[2] << 16 ) |
	       ( (unsigned char)m[1] << 8 ) |
	         (unsigned char)m[0];
}
static uint64_t from_my_64(char *m) {
	return 0;
	/*
	return (uint64_t)(
	       ( (unsigned char)m[7] << 64 ) |
	       ( (unsigned char)m[6] << 56 ) |
	       ( (unsigned char)m[5] << 48 ) |
	       ( (unsigned char)m[4] << 40 ) |
	       ( (unsigned char)m[3] << 32 ) |
	       ( (unsigned char)m[2] << 16 ) |
	       ( (unsigned char)m[1] << 8 ) |
	         (unsigned char)m[0] );
	*/
}
static void to_my_2(int value, char *m) {
	m[1] = value >> 8;
	m[0] = value;
}
static void to_my_3(int value, char *m) {
	m[2] = value >> 16;
	m[1] = value >> 8;
	m[0] = value;
}
static void to_my_4(int value, char *m) {
	m[3] = value >> 24;
	m[2] = value >> 16;
	m[1] = value >> 8;
	m[0] = value;
}

/* length coded binary
  0-250        0           = value of first byte
  251          0           column value = NULL
	                        only appropriate in a Row Data Packet
  252          2           = value of following 16-bit word
  253          3           = value of following 24-bit word
  254          8           = value of following 64-bit word
*/
static int my_lcb(char *m, uint32_t *r,  char *nul) {
	switch ((unsigned char)m[0]) {
	case 251: *r = 0;                   *nul=1; return 1;
	case 252: *r = from_my_16(&m[1]);   *nul=0; return 3;
	case 253: *r = from_my_32(&m[1]);   *nul=0; return 4;
	case 254: *r = from_my_64(&m[1]);   *nul=0; return 5;
	default:  *r = (unsigned char)m[0]; *nul=0; return 1;
	}
}

static inline void strncpyz(char *d, char *s, int l) {
	memcpy(d, s, l);
	d[l] = '\0';
}

enum my_response_t {
	MYSAC_RET_EOF = 1000,
	MYSAC_RET_OK,
	MYSAC_RET_ERROR,
	MYSAC_RET_DATA
};

static int my_response(MYSAC *m) {
	int i;
	int err;
	int errcode;

	switch (m->readst) {

	case 0:
		m->len = 0;
		m->readst = 1;

	/* read length */
	case 1:
		err = mysac_read(m->fd, m->buf + m->len,
		                 4 - m->len, &errcode);
		if (err == -1) {
			m->errorcode = errcode;
			return errcode;
		}

		m->len += err;
		if (m->len < 4) {
			m->errorcode = MYSAC_WANT_READ;
			return MYSAC_WANT_READ;
		}

		/* decode */
		m->packet_length = from_my_24(&m->buf[0]);

		/* packet number */
		m->packet_number = m->buf[3];

		/* update read state */
		m->readst = 2;
		m->len = 0;

	/* read data */
	case 2:
		err = mysac_read(m->fd, m->buf + m->len,
		                 m->packet_length - m->len, &errcode);
		if (err == -1)
			return errcode;

		m->len += err;
		if (m->len < m->packet_length) {
			m->errorcode = MYSAC_WANT_READ;
			return MYSAC_WANT_READ;
		}

		/* re-init eof */
		m->readst = 3;
		m->eof = 1;

	/* decode data */
	case 3:

		/* error */
		if ((unsigned char)m->buf[0] == 255) {
		
			/* defined mysql error */
			if (m->packet_length > 3) {
	
				/* read error code */
				m->errorcode = from_my_16(&m->buf[1]);
			}
	
			/* unknown error */
			else
				m->errorcode = CR_UNKNOWN_ERROR;
	
			return MYSAC_RET_ERROR;
		}
	
		/* EOF marker: marque la fin d'une serie
			(la fin des headers dans une requete) */
		else if ((unsigned char)m->buf[0] == 254) {
			m->warnings = from_my_16(&m->buf[1]);
			m->status = from_my_16(&m->buf[3]);
			m->eof = 1;
			return MYSAC_RET_EOF;
		}
	
		/* success */
		else if ((unsigned char)m->buf[0] == 0) {
	
			/* affected rows (wireshark donne 1 octet, mais en affiche 2 ...) */
			m->affected_rows = from_my_16(&m->buf[1]);
	
			/* server status */
			m->status = from_my_16(&m->buf[3]);
	
			/* server status */
			m->warnings = from_my_16(&m->buf[5]);
	
			return MYSAC_RET_OK;
		}
	
		/* read response ... 
		 *
		 * Result Set Packet			  1-250 (first byte of Length-Coded Binary)
		 * Field Packet					 1-250 ("")
		 * Row Data Packet				 1-250 ("")
		 */
		else
			return MYSAC_RET_DATA;
	}

	m->errorcode = CR_UNKNOWN_ERROR;
	return MYSAC_RET_ERROR;
}

MYSAC *mysac_init(MYSAC *mysac) {
	MYSAC *m;

	/* memory */
	if (mysac == NULL) {
		m = malloc(sizeof(MYSAC));
		if (m == NULL)
			return NULL;
		m->free_it = 1;
	}
	
	else
		m = mysac;

	/* init */
	memset(m, 0, sizeof(MYSAC));
	m->qst = MYSAC_START;
}

void mysac_setup(MYSAC *mysac, const char *my_addr, const char *user,
                 const char *passwd, const char *db,
                 unsigned long client_flag) {
	mysac->addr     = my_addr;
	mysac->login    = user;
	mysac->password = passwd;
	mysac->database = db;
	mysac->flags    = client_flag;
}

int mysac_connect(MYSAC *mysac) {
	int err;
	int errcode;
	int i;
	int len;

	switch (mysac->qst) {

	/***********************************************
	 network connexion
	***********************************************/
	case MYSAC_START:
		err = mysac_socket_connect(mysac->addr, &mysac->fd);
		if (err != 0) {
			mysac->qst = MYSAC_START;
			mysac->errorcode = err;
			return err;
		}
		mysac->qst = MYSAC_CONN_CHECK;
		return MYSAC_WANT_READ;

	/***********************************************
	 check network connexion
	***********************************************/
	case MYSAC_CONN_CHECK:
		err = mysac_socket_connect_check(mysac->fd);
		if (err != 0) {
			close(mysac->fd);
			mysac->qst = MYSAC_START;
			mysac->errorcode = err;
			return err;
		}
		mysac->qst = MYSAC_READ_GREATINGS;
		mysac->len = 0;
		mysac->readst = 0;

	/***********************************************
	 read greatings
	***********************************************/
	case MYSAC_READ_GREATINGS:

		err = my_response(mysac);

		if (err == MYSAC_WANT_READ)
			return MYSAC_WANT_READ;

		/* error */
		else if (err == MYSAC_RET_ERROR)
			return mysac->errorcode;

		/* ok */
		else if (err != MYSAC_RET_DATA) {
			mysac->errorcode = CR_SERVER_HANDSHAKE_ERR;
			return mysac->errorcode;
		}

		/* decode greatings */
		i = 0;

		/* protocol */
		mysac->protocol = mysac->buf[i];
		i++;

		/* version */
		mysac->version = &mysac->buf[i];

		/* search \0 */
		while (mysac->buf[i] != 0)
			i++;
		i++;

		/* thread id */
		mysac->threadid = from_my_32(&mysac->buf[i]);

		/* first part of salt */
		strncpy(mysac->salt, &mysac->buf[i+4], SCRAMBLE_LENGTH_323);
		i += 4 + SCRAMBLE_LENGTH_323 + 1;

		/* options */
		mysac->options = from_my_16(&mysac->buf[i]);

		/* charset */
		mysac->charset = mysac->buf[i+2];

		/* server status */
		mysac->status = from_my_16(&mysac->buf[i+3]);

		/* salt part 2 */
		strncpy(mysac->salt + SCRAMBLE_LENGTH_323, &mysac->buf[i+5+13],
		        SCRAMBLE_LENGTH - SCRAMBLE_LENGTH_323);
		mysac->salt[SCRAMBLE_LENGTH] = '\0';

		/* checks */
		if (mysac->protocol != PROTOCOL_VERSION)
			return CR_VERSION_ERROR;

		/********************************
		  prepare auth packet 
		********************************/

		/* set m->buf number */
		mysac->packet_number++;
		mysac->buf[3] = mysac->packet_number;
		
		/* set options */
		if (mysac->options & CLIENT_LONG_PASSWORD)
			mysac->flags |= CLIENT_LONG_PASSWORD;
		mysac->flags |= CLIENT_LONG_FLAG   |
		                CLIENT_PROTOCOL_41 |
		                CLIENT_SECURE_CONNECTION;
		to_my_2(mysac->flags, &mysac->buf[4]);
		
		/* set extended options */
		to_my_2(0, &mysac->buf[6]);

		/* max m->bufs */
		to_my_4(0x40000000, &mysac->buf[8]);

		/* charset */
		/* 8: swedish */
		mysac->buf[12] = 8;
		
		/* 24 unused */
		memset(&mysac->buf[13], 0, 24);
		
		/* username */
		strcpy(&mysac->buf[36], mysac->login);
		i = 36 + strlen(mysac->login) + 1;

		/* password CLIENT_SECURE_CONNECTION */
		if (mysac->options & CLIENT_SECURE_CONNECTION) {

			/* the password hash len */
			mysac->buf[i] = SCRAMBLE_LENGTH;
			i++;
			scramble(&mysac->buf[i], mysac->salt, mysac->password);
			i += SCRAMBLE_LENGTH;
		}
		
		/* password ! CLIENT_SECURE_CONNECTION */
		else {
			scramble_323(&mysac->buf[i], mysac->salt, mysac->password);
			i += SCRAMBLE_LENGTH_323 + 1;
		}
		
		/* Add database if needed */
		if (mysac->options & CLIENT_CONNECT_WITH_DB) {
			/* TODO : debordement de buffer */
			len = strlen(mysac->database);
			memcpy(&mysac->buf[i], mysac->database, len);
			i += len;
			mysac->buf[i] = '\0';
		}

		/* len */
		to_my_3(i-4, &mysac->buf[0]);
		mysac->len = i;
		mysac->send = mysac->buf;
		mysac->qst = MYSAC_SEND_AUTH_1;

	/***********************************************
	 send paquet
	***********************************************/
	case MYSAC_SEND_AUTH_1:
		err = mysac_write(mysac->fd, mysac->send, mysac->len, &errcode);

		if (err == -1)
			return errcode;

		mysac->len -= err;
		mysac->send += err;
		if (mysac->len > 0)
			return MYSAC_WANT_WRITE;

		mysac->qst = MYSAC_RECV_AUTH_1;
		mysac->readst = 0;

	/***********************************************
	 read response 1
	***********************************************/
	case_MYSAC_RECV_AUTH_1:
	case MYSAC_RECV_AUTH_1:
	/*
		MYSAC_RET_EOF,
		MYSAC_RET_OK,
		MYSAC_RET_ERROR,
		MYSAC_RET_DATA
	*/
		err = my_response(mysac);

		if (err == MYSAC_WANT_READ)
			return MYSAC_WANT_READ;

		/* error */
		if (err == MYSAC_RET_ERROR)
			return mysac->errorcode;

		/* ok */
		else if (err == MYSAC_RET_OK)
			return 0;

		/*
		   By sending this very specific reply server asks us to send scrambled
		   password in old format.
		*/
		else if (mysac->packet_length == 1 && err == MYSAC_RET_EOF && 
		         mysac->options & CLIENT_SECURE_CONNECTION) {
			/* continue special paquet after conditions */
		}

		/* protocol error */
		else {
			mysac->errorcode = CR_SERVER_HANDSHAKE_ERR;
			return mysac->errorcode;
		}

		/* send scrambled password in old format */

		/* set packet number */
		mysac->packet_number++;
		mysac->buf[3] = mysac->packet_number;
		
		/* send scrambled password in old format. */
		scramble_323(&mysac->buf[4], mysac->salt, mysac->password);
		mysac->buf[4+SCRAMBLE_LENGTH_323] = '\0';

		/* len */
		to_my_3(SCRAMBLE_LENGTH_323+1, &mysac->buf[0]);
		mysac->qst = MYSAC_SEND_AUTH_2;
		mysac->len = SCRAMBLE_LENGTH_323 + 1 + 4;
		mysac->send = mysac->buf;

	/* send scrambled password in old format */
	case MYSAC_SEND_AUTH_2:
		err = mysac_write(mysac->fd, mysac->send, mysac->len, &errcode);

		if (err == -1)
			return errcode;

		mysac->len -= err;
		mysac->send += err;
		if (mysac->len > 0)
			return MYSAC_WANT_WRITE;

		mysac->qst = MYSAC_RECV_AUTH_1;
		mysac->readst = 0;
		goto case_MYSAC_RECV_AUTH_1;
		
	}

	return 0;
}

int mysac_set_database(MYSAC *mysac, const char *database) {
	int i;
	int len;

	/* set packet number */
	mysac->buf[3] = 0;

	/* set mysql command */
	mysac->buf[4] = COM_INIT_DB;

	/* build sql query */
	i = strlen(database);
	memcpy(&mysac->buf[5], database, i);

	/* len */
	to_my_3(i + 1, &mysac->buf[0]);

	/* send params */
	mysac->send = mysac->buf;
	mysac->len = i + 5;
	mysac->qst = MYSAC_SEND_INIT_DB;

	return 0;
}

int mysac_send_database(MYSAC *mysac) {
	int err;
	int errcode;

	switch (mysac->qst) {

	/**********************************************************
	*
	* send query on network
	*
	**********************************************************/
	case MYSAC_SEND_INIT_DB:
		err = mysac_write(mysac->fd, mysac->send, mysac->len, &errcode);

		if (err == -1)
			return errcode;

		mysac->len -= err;
		mysac->send += err;
		if (mysac->len > 0)
			return MYSAC_WANT_WRITE;
		mysac->qst = MYSAC_RECV_INIT_DB;
		mysac->readst = 0;
	
	/**********************************************************
	*
	* receive
	*
	**********************************************************/
	case MYSAC_RECV_INIT_DB:
		err = my_response(mysac);

		if (err == MYSAC_WANT_READ)
			return MYSAC_WANT_READ;

		/* error */
		if (err == MYSAC_RET_ERROR)
			return mysac->errorcode;

		/* protocol error */
		else if (err == MYSAC_RET_OK)
			return 0;

		else {
			mysac->errorcode = CR_SERVER_HANDSHAKE_ERR; /* TODO: pas la bonne erreur */
			return mysac->errorcode;
		}
	}
}

int mysac_set_query(MYSAC *mysac, const char *fmt, ...) {
	va_list ap;
	int len;

	/* set packet number */
	mysac->buf[3] = 0;

	/* set mysql command */
	mysac->buf[4] = COM_QUERY;

	/* build sql query */
	va_start(ap, fmt);
	len = vsnprintf(&mysac->buf[5], MYSAC_BUFFER_SIZE-5, fmt, ap);
	if (len >= MYSAC_BUFFER_SIZE - 5)
		return -1;

	/* len */
	to_my_3(len + 1, &mysac->buf[0]);

	/* send params */
	mysac->send = mysac->buf;
	mysac->len = len + 5;
	mysac->qst = MYSAC_SEND_QUERY;

	return 0;
}


int mysac_send_query(MYSAC *mysac) {
	int err;
	int errcode;
	int i;
	uint32_t size;
	char nul;

	switch (mysac->qst) {

	/**********************************************************
	*
	* send query on network
	*
	**********************************************************/
	case MYSAC_SEND_QUERY:
		err = mysac_write(mysac->fd, mysac->send, mysac->len, &errcode);

		if (err == -1)
			return errcode;

		mysac->len -= err;
		mysac->send += err;
		if (mysac->len > 0)
			return MYSAC_WANT_WRITE;
		mysac->qst = MYSAC_RECV_QUERY_COLNUM;
		mysac->readst = 0;
	
	/**********************************************************
	*
	* receive
	*
	**********************************************************/
	case MYSAC_RECV_QUERY_COLNUM:
		err = my_response(mysac);

		if (err == MYSAC_WANT_READ)
			return MYSAC_WANT_READ;

		/* error */
		if (err == MYSAC_RET_ERROR)
			return mysac->errorcode;

		/* protocol error */
		else if (err != MYSAC_RET_DATA) {
			mysac->errorcode = CR_SERVER_HANDSHAKE_ERR; /* TODO: pas la bonne erreur */
			return mysac->errorcode;
		}

		/* get nb col TODO: pas sur que ce soit un byte */
		mysac->nb_cols = mysac->buf[0];
		mysac->read_id = 0;
		
		mysac->qst = MYSAC_RECV_QUERY_COLDESC;
	
	/**********************************************************
	*
	* receive column description
	*
	**********************************************************/
	case_MYSAC_RECV_QUERY_COLDESC:
	mysac->readst = 0;

	case MYSAC_RECV_QUERY_COLDESC:

		err = my_response(mysac);

		if (err == MYSAC_WANT_READ)
			return MYSAC_WANT_READ;

		/* error */
		if (err == MYSAC_RET_ERROR)
			return mysac->errorcode;

		/* protocol error */
		else if (err != MYSAC_RET_DATA) {
			mysac->errorcode = CR_SERVER_HANDSHAKE_ERR; /* TODO: pas la bonne erreur */
			return mysac->errorcode;
		}

		/*
		VERSION 4.0
		 Bytes                      Name
		 -----                      ----
		 n (Length Coded String)    table
		 n (Length Coded String)    name
		 4 (Length Coded Binary)    length
		 2 (Length Coded Binary)    type
		 2 (Length Coded Binary)    flags
		 1                          decimals
		 n (Length Coded Binary)    default
		 
		 -> VERSION 4.1
		 Bytes                      Name
		 -----                      ----
		 n (Length Coded String)    catalog
		 n (Length Coded String)    db
		 n (Length Coded String)    table
		 n (Length Coded String)    org_table
		 n (Length Coded String)    name
		 n (Length Coded String)    org_name
		 1                          (filler)
		 2                          charsetnr
		 4                          length
		 1                          type
		 2                          flags
		 1                          decimals
		 2                          (filler), always 0x00
		 n (Length Coded Binary)    default
		*/
	
		mysac->cols[mysac->read_id].mf.org_name = "";
		mysac->cols[mysac->read_id].mf.table = "";
		mysac->cols[mysac->read_id].mf.org_table = "";
		mysac->cols[mysac->read_id].mf.db = "";
		mysac->cols[mysac->read_id].mf.catalog = "";
		mysac->cols[mysac->read_id].mf.def = "";
		mysac->cols[mysac->read_id].mf.org_name_length = 0;
		mysac->cols[mysac->read_id].mf.table_length = 0;
		mysac->cols[mysac->read_id].mf.org_table_length = 0;
		mysac->cols[mysac->read_id].mf.db_length = 0;
		mysac->cols[mysac->read_id].mf.catalog_length = 0;
		mysac->cols[mysac->read_id].mf.def_length = 0;
	
		i = 0;

		/* n (Length Coded String)    catalog */
		i += my_lcb(&mysac->buf[i], &size, &nul);
		i += size;
	
		/* n (Length Coded String)    db */
		i += my_lcb(&mysac->buf[i], &size, &nul);
		i += size;
	
		/* n (Length Coded String)    table */
		i += my_lcb(&mysac->buf[i], &size, &nul);
		i += size;
	
		/* n (Length Coded String)    org_table */
		i += my_lcb(&mysac->buf[i], &size, &nul);
		i += size;
	
		/* n (Length Coded String)    name */
		i += my_lcb(&mysac->buf[i], &size, &nul);
		strncpyz(mysac->cols[mysac->read_id].colname, &mysac->buf[i], size);
		mysac->cols[mysac->read_id].mf.name = mysac->cols[mysac->read_id].colname;
		mysac->cols[mysac->read_id].mf.name_length = size;
		i += size;
	
		/* n (Length Coded String)    org_name */
		i += my_lcb(&mysac->buf[i], &size, &nul);
		i += size;
	
		/* (filler) */
		i += 1;
	
		/* charset */
		mysac->cols[mysac->read_id].mf.charsetnr = from_my_16(&mysac->buf[i]);
		i += 2;
	
		/* length */
		mysac->cols[mysac->read_id].mf.length = from_my_32(&mysac->buf[i]);
		i += 4;
	
		/* type */
		mysac->cols[mysac->read_id].mf.type = mysac->buf[i];
		i += 1;
	
		/* flags */
		mysac->cols[mysac->read_id].mf.flags = from_my_24(&mysac->buf[i]);
		i += 2;
	
		/* decimals */
		mysac->cols[mysac->read_id].mf.decimals = mysac->buf[i];
		i += 1;
	
		/* filler */
		i += 2;
	
		/* default */
		i += my_lcb(&mysac->buf[i], &size, &nul);
		i += size;

		mysac->read_id++;
		if (mysac->read_id < mysac->nb_cols)
			goto case_MYSAC_RECV_QUERY_COLDESC;
		
		mysac->readst = 0;
		mysac->qst = MYSAC_RECV_QUERY_EOF1;
	
	/**********************************************************
	*
	* receive EOF
	*
	**********************************************************/
	case MYSAC_RECV_QUERY_EOF1:
		err = my_response(mysac);

		if (err == MYSAC_WANT_READ)
			return MYSAC_WANT_READ;

		/* error */
		if (err == MYSAC_RET_ERROR)
			return mysac->errorcode;

		/* protocol error */
		else if (err != MYSAC_RET_EOF) {
			mysac->errorcode = CR_SERVER_HANDSHAKE_ERR; /* TODO: pas la bonne erreur */
			return mysac->errorcode;
		}

		mysac->qst = MYSAC_RECV_QUERY_DATA;

	/**********************************************************
	*
	* read data
	*
	**********************************************************/
	case_MYSAC_RECV_QUERY_DATA:
	mysac->readst = 0;

	case MYSAC_RECV_QUERY_DATA:
		exit(0);

	}
}

