#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <events.h>
#include <arpa/inet.h>

#include <mysql/mysql.h>

int myfd;

enum my_query_st {
	MY_READ_NUM,
	MY_READ_HEADER,
	MY_READ_LINE
};

#define MY_MAX_COL_NAME 256

struct my_col_head {
	char name[MY_MAX_COL_NAME+1];
};

struct my {
	char buf[1024*1024];

	unsigned int packet_length;
	unsigned int packet_number;

	/* connect */
	unsigned int protocol;
	char *version;
	unsigned int threadid;
	char salt[SCRAMBLE_LENGTH + 1];
	unsigned int options;
	unsigned int charset;
	unsigned int status;
	unsigned int affected_rows;
	unsigned int warnings;
	unsigned int errorcode;

	/* user */
	char *login;
	char *password;
	char *query;
	char *database;

	/* query */
	enum my_query_st qst;
	int nb_cols;
	int read_id;
	struct my_col_head cols[255];
};

const char *my_type[] = {
	[MYSQL_TYPE_DECIMAL]     = "MYSQL_TYPE_DECIMAL",
	[MYSQL_TYPE_TINY]        = "MYSQL_TYPE_TINY",
	[MYSQL_TYPE_SHORT]       = "MYSQL_TYPE_SHORT",
	[MYSQL_TYPE_LONG]        = "MYSQL_TYPE_LONG",
	[MYSQL_TYPE_FLOAT]       = "MYSQL_TYPE_FLOAT",
	[MYSQL_TYPE_DOUBLE]      = "MYSQL_TYPE_DOUBLE",
	[MYSQL_TYPE_NULL]        = "MYSQL_TYPE_NULL",
	[MYSQL_TYPE_TIMESTAMP]   = "MYSQL_TYPE_TIMESTAMP",
	[MYSQL_TYPE_LONGLONG]    = "MYSQL_TYPE_LONGLONG",
	[MYSQL_TYPE_INT24]       = "MYSQL_TYPE_INT24",
	[MYSQL_TYPE_DATE]        = "MYSQL_TYPE_DATE",
	[MYSQL_TYPE_TIME]        = "MYSQL_TYPE_TIME",
	[MYSQL_TYPE_DATETIME]    = "MYSQL_TYPE_DATETIME",
	[MYSQL_TYPE_YEAR]        = "MYSQL_TYPE_YEAR",
	[MYSQL_TYPE_NEWDATE]     = "MYSQL_TYPE_NEWDATE",
	[MYSQL_TYPE_VARCHAR]     = "MYSQL_TYPE_VARCHAR",
	[MYSQL_TYPE_BIT]         = "MYSQL_TYPE_BIT",
	[MYSQL_TYPE_NEWDECIMAL]  = "MYSQL_TYPE_NEWDECIMAL",
	[MYSQL_TYPE_ENUM]        = "MYSQL_TYPE_ENUM",
	[MYSQL_TYPE_SET]         = "MYSQL_TYPE_SET",
	[MYSQL_TYPE_TINY_BLOB]   = "MYSQL_TYPE_TINY_BLOB",
	[MYSQL_TYPE_MEDIUM_BLOB] = "MYSQL_TYPE_MEDIUM_BLOB",
	[MYSQL_TYPE_LONG_BLOB]   = "MYSQL_TYPE_LONG_BLOB",
	[MYSQL_TYPE_BLOB]        = "MYSQL_TYPE_BLOB",
	[MYSQL_TYPE_VAR_STRING]  = "MYSQL_TYPE_VAR_STRING",
	[MYSQL_TYPE_STRING]      = "MYSQL_TYPE_STRING",
	[MYSQL_TYPE_GEOMETRY]    = "MYSQL_TYPE_GEOMETRY"
};

const char *my_flags[] = {
	[NOT_NULL_FLAG] = "NOT_NULL_FLAG",
	[PRI_KEY_FLAG] = "PRI_KEY_FLAG",
	[UNIQUE_KEY_FLAG] = "UNIQUE_KEY_FLAG",
	[MULTIPLE_KEY_FLAG] = "MULTIPLE_KEY_FLAG",
	[BLOB_FLAG] = "BLOB_FLAG",
	[UNSIGNED_FLAG] = "UNSIGNED_FLAG",
	[ZEROFILL_FLAG] = "ZEROFILL_FLAG",
	[BINARY_FLAG] = "BINARY_FLAG"
};

static uint32_t from_my_2(char *m) {
	return ( (unsigned char)m[1] << 8 ) |
	         (unsigned char)m[0];
}
static uint32_t from_my_3(char *m) {
	return ( (unsigned char)m[2] << 16 ) |
	       ( (unsigned char)m[1] << 8 ) | 
	         (unsigned char)m[0];
}
static uint32_t from_my_4(char *m) {
	return ( (unsigned char)m[3] << 24 ) |
	       ( (unsigned char)m[2] << 16 ) |
	       ( (unsigned char)m[1] << 8 ) |
	         (unsigned char)m[0];
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

void my_response(int fd, void *arg);
void my_auth_response(int fd, void *arg);
void my_select_db_response(int fd, void *arg);
void my_query_response(int fd, void *arg);

void my_send_query(int fd, void *arg) {
	struct my *m = arg;
	int i;

	/* set packet number */
	m->buf[3] = 0;

	/* set sql command */
	m->buf[4] = COM_QUERY;

	/* copy database name */
	i = strlen(m->query);
	memcpy(&m->buf[5], m->query, i);
	i++;

	/* len */
	to_my_3(i, &m->buf[0]);

	/* send packet */
	write(fd, m->buf, i+4);

	/* init query read */
	m->qst = MY_READ_NUM;

	ev_poll_fd_clr(fd, EV_POLL_WRITE);
	ev_poll_fd_set(fd, EV_POLL_READ, my_query_response, arg);
}

void my_select_database(int fd, void *arg) {
	struct my *m = arg;
	int i;

	/* set packet number */
	m->buf[3] = 0;

	/* set sql command */
	m->buf[4] = COM_INIT_DB;

	/* copy database name */
	i = strlen(m->database);
	memcpy(&m->buf[5], m->database, i);
	i++;

	/* len */
	to_my_3(i, &m->buf[0]);

	/* send pâcket */
	write(fd, m->buf, i+4);

	ev_poll_fd_clr(fd, EV_POLL_WRITE);
	ev_poll_fd_set(fd, EV_POLL_READ, my_select_db_response, arg);
}

void my_read_def(struct my *m) {
	int l;
	int i = 0;
	int j;
	int flag;
	int size;

	/* 6 noms longueur / valeur */
	write(2, "[", 1);

	/* type longueur valeur */
	l = (unsigned char)m->buf[i];
	i++;
	if (l == 0xfc) {
		l = from_my_2(&m->buf[i]);
		i += 2;
	}
	write(2, &m->buf[i], l);
	i += l;
	write(2, "] [", 3);

	/* type longueur valeur */
	l = (unsigned char)m->buf[i];
	i++;
	if (l == 0xfc) {
		l = from_my_2(&m->buf[i]);
		i += 2;
	}
	write(2, &m->buf[i], l);
	i += l;
	write(2, "] [", 3);

	/* type longueur valeur */
	l = (unsigned char)m->buf[i];
	i++;
	if (l == 0xfc) {
		l = from_my_2(&m->buf[i]);
		i += 2;
	}
	write(2, &m->buf[i], l);
	i += l;
	write(2, "] [", 3);

	/* type longueur valeur */
	l = (unsigned char)m->buf[i];
	i++;
	if (l == 0xfc) {
		l = from_my_2(&m->buf[i]);
		i += 2;
	}
	write(2, &m->buf[i], l);
	i += l;
	write(2, "]\n", 2);

	/* type longueur valeur */
	/* XXX: coloumn name */
	l = (unsigned char)m->buf[i];
	i++;
	if (l == 0xfc) {
		l = from_my_2(&m->buf[i]);
		i += 2;
	}
	memcpy(m->cols[m->read_id].name, &m->buf[i], l);
	m->cols[m->read_id].name[l] = '\0';
	i += l;
	fprintf(stderr, "column name(%d)=[%s]", l, m->cols[m->read_id].name);

	/* type longueur valeur */
	write(2, "[", 1);
	l = (unsigned char)m->buf[i];
	i++;
	if (l == 0xfc) {
		l = from_my_2(&m->buf[i]);
		i += 2;
	}
	write(2, &m->buf[i], l);
	i += l;
	write(2, "]\n", 2);

	/* type longueur valeur */
	l = (unsigned char)m->buf[i];
	i++;
	j = i;
	/* display */
	l += i;
	for (; i < l; i++) {
		/* taille */
		if (i == j + 2) {
			size = from_my_4(&m->buf[i]);
			fprintf(stderr, "\n%02x %02x %02x %02x: size=%d\n",
			        (unsigned char)m->buf[i],
			        (unsigned char)m->buf[i+1],
			        (unsigned char)m->buf[i+2],
			        (unsigned char)m->buf[i+3],
			        size);
			i+=3;
		}
		else if (i == j + 6)
			fprintf(stderr, "%02x: type=%s\n", (unsigned char)m->buf[i],
			                            my_type[(unsigned char)m->buf[i]]);
		else if (i == j + 7) {
			flag = from_my_3(&m->buf[i]);
			fprintf(stderr, "%02x %02x %02x: flags={",
			        (unsigned char)m->buf[i],
			        (unsigned char)m->buf[i+1],
			        (unsigned char)m->buf[i+2]);
			i+=2;

			if ((flag & NOT_NULL_FLAG) != 0)
				fprintf(stderr, "NOT_NULL_FLAG, ");
			if ((flag & PRI_KEY_FLAG) != 0)
				fprintf(stderr, "PRI_KEY_FLAG, ");
			if ((flag & UNIQUE_KEY_FLAG) != 0)
				fprintf(stderr, "UNIQUE_KEY_FLAG, ");
			if ((flag & MULTIPLE_KEY_FLAG) != 0)
				fprintf(stderr, "MULTIPLE_KEY_FLAG, ");
			if ((flag & BLOB_FLAG) != 0)
				fprintf(stderr, "BLOB_FLAG, ");
			if ((flag & UNSIGNED_FLAG) != 0)
				fprintf(stderr, "UNSIGNED_FLAG, ");
			if ((flag & ZEROFILL_FLAG) != 0)
				fprintf(stderr, "ZEROFILL_FLAG, ");
			if ((flag & BINARY_FLAG) != 0)
				fprintf(stderr, "BINARY_FLAG, ");

			if ((flag & ENUM_FLAG) != 0)
				fprintf(stderr, "ENUM_FLAG, ");
			if ((flag & AUTO_INCREMENT_FLAG) != 0)
				fprintf(stderr, "AUTO_INCREMENT_FLAG, ");
			if ((flag & TIMESTAMP_FLAG) != 0)
				fprintf(stderr, "TIMESTAMP_FLAG, ");
			if ((flag & SET_FLAG) != 0)
				fprintf(stderr, "SET_FLAG, ");
			if ((flag & NO_DEFAULT_VALUE_FLAG) != 0)
				fprintf(stderr, "NO_DEFAULT_VALUE_FLAG, ");
			if ((flag & NUM_FLAG) != 0)
				fprintf(stderr, "NUM_FLAG, ");
			if ((flag & PART_KEY_FLAG) != 0)
				fprintf(stderr, "PART_KEY_FLAG, ");
			if ((flag & GROUP_FLAG) != 0)
				fprintf(stderr, "GROUP_FLAG, ");

			if ((flag & UNIQUE_FLAG) != 0)
				fprintf(stderr, "UNIQUE_FLAG, ");
			if ((flag & BINCMP_FLAG) != 0)
				fprintf(stderr, "BINCMP_FLAG, ");

			fprintf(stderr, "}\n");
		}
		else
			fprintf(stderr, "%02x ", (unsigned char)m->buf[i]);
	}
	fprintf(stderr, "\n\n");
	fflush(stderr);
}

void my_response(int fd, void *arg) {
	struct my *m = arg;
	int i;

	/* read length */
	read(fd, m->buf, 4);

	/* decode */
	m->packet_length = from_my_3(&m->buf[0]);

	/* packet number */
	m->packet_number = m->buf[3];

	/* read data */
	read(fd, m->buf, m->packet_length);

	/* error */
	if ((unsigned char)m->buf[0] == 255) {
	
		/* defined mysql error */
		if (m->packet_length > 3) {

			/* read error code */
			m->errorcode = from_my_2(&m->buf[1]);

			/* write error msg */
			write (2, &m->buf[3], m->packet_length - 3);
			write (2, "\n", 1);
			exit(1);
		}

		/* unknown error */
		else
			exit(1);
	}

	/* EOF marker: marque la fin d'une serie
	   (la fin des headers dans une requete) */
	else if ((unsigned char)m->buf[0] == 254) {
		m->warnings = from_my_2(&m->buf[1]);
		m->status = from_my_2(&m->buf[3]);
	}

	/* success */
	else if ((unsigned char)m->buf[0] == 0) {

		/* affected rows (wireshark donne 1 octet, mais en affiche 2 ...) */
		m->affected_rows = from_my_2(&m->buf[1]);

		/* server status */
		m->status = from_my_2(&m->buf[3]);

		/* server status */
		m->warnings = from_my_2(&m->buf[5]);
	}

	/* read response ... */
	else {

		switch (m->qst) {

		/* nombre de colonnes */
		case MY_READ_NUM:
			m->nb_cols = m->buf[0];
			m->read_id = 0;
			m->qst = MY_READ_HEADER;
			break;

		/* lecture des headers de colonnes */
		case MY_READ_HEADER:
			my_read_def(m);
			m->read_id++;
			if (m->read_id == m->nb_cols) {
				m->read_id = 0;
				m->qst = MY_READ_LINE;
			}
			break;

		/* lecture de chaque lignes */
		case MY_READ_LINE:
			break;
		}

	}
}

void my_auth_response(int fd, void *arg) {
	my_response(fd, arg);
	ev_poll_fd_clr(fd, EV_POLL_READ);
	ev_poll_fd_set(fd, EV_POLL_WRITE, my_select_database, arg);
}

void my_select_db_response(int fd, void *arg) {
	my_response(fd, arg);
	ev_poll_fd_clr(fd, EV_POLL_READ);
	ev_poll_fd_set(fd, EV_POLL_WRITE, my_send_query, arg);
}

void my_query_response(int fd, void *arg) {
	my_response(fd, arg);
	//exit(0);
}

void my_auth(int fd, void *arg) {
	struct my *m = arg;
	int i;

	/* set m->buf number */
	m->buf[3] = 1;

	/* set options */
	to_my_2(CLIENT_LONG_PASSWORD     |
	        CLIENT_LONG_FLAG         |
	        CLIENT_PROTOCOL_41       |
	        CLIENT_SECURE_CONNECTION,
	        &m->buf[4]);

	/* set extended options */
	to_my_2(0, &m->buf[6]);

	/* max m->bufs */
	to_my_4(0x40000000, &m->buf[8]);

	/* charset */
	/* 8: swedish */
	m->buf[12] = 8;

	/* 24 unused */
	memset(&m->buf[13], 0, 24);

	/* username */
	strcpy(&m->buf[36], m->login);
	i = 36 + strlen(m->login) + 1;

	/* the password hash len */
	m->buf[i] = SCRAMBLE_LENGTH;
	i++;

	/* password */
	scramble(&m->buf[i], m->salt, m->password);
	i += SCRAMBLE_LENGTH;

	/* len */
	to_my_3(i-4, &m->buf[0]);

	write(fd, m->buf, i);

	ev_poll_fd_clr(fd, EV_POLL_WRITE);
	ev_poll_fd_set(fd, EV_POLL_READ, my_auth_response, arg);
}

void my_read_greatings(int fd, void *arg) {
	struct my *m = arg;
	int i;

	/* read length */
	read(fd, m->buf, 4);

	/* decode */
	m->packet_number = m->buf[3];
	m->packet_length = from_my_3(&m->buf[0]);

	/* read data */
	read(fd, m->buf, m->packet_length);

	/* depiote */

	/* protocol */
	m->protocol = m->buf[0];

	/* version */
	m->version = &m->buf[1];
	i = 1;

	/* search \0 */
	while (m->buf[i] != 0)
		i++;
	i++;

	/* thread id */
	m->threadid = from_my_4(&m->buf[i]);

	/* first part of salt */
	strncpy(m->salt, &m->buf[i+4], SCRAMBLE_LENGTH_323);
	i += 4 + SCRAMBLE_LENGTH_323 + 1;

	/* options */
	m->options = from_my_2(&m->buf[i]);

	/* charset */
	m->charset = m->buf[i+2];

	/* server status */
	m->status = from_my_2(&m->buf[i+3]);

	/* salt part 2 */
	strncpy(m->salt + SCRAMBLE_LENGTH_323, &m->buf[i+5+13],
	        SCRAMBLE_LENGTH - SCRAMBLE_LENGTH_323);
	m->salt[SCRAMBLE_LENGTH] = '\0';

	ev_poll_fd_clr(fd, EV_POLL_READ);
	ev_poll_fd_set(fd, EV_POLL_WRITE, my_auth, arg);
}

void my_async_connect(int fd, void *arg) {
	if (ev_socket_connect_check(fd) != EV_OK)
		exit(1);
	ev_poll_fd_set(fd, EV_POLL_READ, my_read_greatings, arg);
}

int main(int argc, char *argv[]) {
	struct ev_timeout_basic_node tmout;
	struct my m;

	poll_select_register();

	ev_timeout_init(&tmout);
	ev_poll_init(100, &tmout);

	m.login = "root";
	m.password = "root";
	m.database = "tests";
	if (argc == 2)
		m.query = argv[1];
	else
		m.query = "SELECT COUNT(*) AS COUNT FROM test;";

	myfd = ev_socket_connect("127.0.0.1:3306");
	if (myfd < 0)
		exit(1);

	ev_poll_fd_set(myfd, EV_POLL_READ, my_async_connect, &m);

	ev_poll_poll(1);
}
