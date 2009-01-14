#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <events.h>
#include <arpa/inet.h>

#include <mysql/mysql.h>

int myfd;

/*
  (Result Set Header Packet)  the number of columns
  (Field Packets)             column descriptors
  (EOF Packet)                marker: end of Field Packets
  (Row Data Packets)          row contents
  (EOF Packet)                marker: end of Data Packets
*/
enum my_query_st {
	MY_READ_NUM,
	MY_READ_HEADER,
	MY_READ_LINE
};

#define MY_MAX_COL_NAME 256

/*
 n (Length Coded String)    catalog
 n (Length Coded String)    db
 n (Length Coded String)    table
 n (Length Coded String)    org_table
 n (Length Coded String)    name
 n (Length Coded String)    org_name
 2                          charsetnr
 4                          length
 1                          type
 2                          flags
 1                          decimals
 2                          (filler), always 0x00
 n (Length Coded Binary)    default
*/
struct my_col_head {
	char name[MY_MAX_COL_NAME+1];
	uint16_t charsetnr;
	uint16_t flags;
	uint32_t length;
	uint8_t type;
	uint8_t decimals;
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

static void strncpyz(char *d, char *s, int l) {
	memcpy(d, s, l);
	d[l] = '\0';
}

void my_read_value(struct my *m) {
	uint32_t size;
	char nul;
	int i = 0;
	int j;

	for (j=0; j<m->nb_cols; j++) {
		fprintf(stderr, "val col %d: ", j);
		i += my_lcb(&m->buf[i], &size,  &nul);
		if (nul == 1)
			fprintf(stderr, "(null)");
		else {
			write(2, &m->buf[i], size);
			i += size;
		}
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "-----------------------------\n");
}

void my_read_def(struct my *m) {
	int l;
	int i = 0;
	int j;
	int flag;
	uint32_t size;
	char nul;
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

	/* n (Length Coded String)    catalog */
	i += my_lcb(&m->buf[i], &size, &nul);
	fprintf(stderr, "catalog: [");
	write(2, &m->buf[i], size);
	write(2, "]\n", 2);
	i += size;

	/* n (Length Coded String)    db */
	i += my_lcb(&m->buf[i], &size, &nul);
	fprintf(stderr, "db: [");
	write(2, &m->buf[i], size);
	write(2, "]\n", 2);
	i += size;

	/* n (Length Coded String)    table */
	i += my_lcb(&m->buf[i], &size, &nul);
	fprintf(stderr, "table: [");
	write(2, &m->buf[i], size);
	write(2, "]\n", 2);
	i += size;

	/* n (Length Coded String)    org_table */
	i += my_lcb(&m->buf[i], &size, &nul);
	fprintf(stderr, "org_table: [");
	write(2, &m->buf[i], size);
	write(2, "]\n", 2);
	i += size;

	/* n (Length Coded String)    name */
	i += my_lcb(&m->buf[i], &size, &nul);
	strncpyz(m->cols[m->read_id].name, &m->buf[i], size);
	fprintf(stderr, "name: [%s]\n", m->cols[m->read_id].name);
	i += size;

	/* n (Length Coded String)    org_name */
	i += my_lcb(&m->buf[i], &size, &nul);
	fprintf(stderr, "org_name: [");
	write(2, &m->buf[i], size);
	write(2, "]\n", 2);
	i += size;

	/* (filler) */
	i += 1;

	/* charset */
	m->cols[m->read_id].charsetnr = from_my_16(&m->buf[i]);
	i += 2;
	fprintf(stderr, "charset: %d\n", m->cols[m->read_id].charsetnr);

	/* length */
	m->cols[m->read_id].length = from_my_32(&m->buf[i]);
	i += 4;
	fprintf(stderr, "length: %d\n", m->cols[m->read_id].length);

	/* type */
	m->cols[m->read_id].type = m->buf[i];
	i += 1;
	fprintf(stderr, "type: %d: %s\n", m->cols[m->read_id].type,
	        my_type[m->cols[m->read_id].type]);

	/* flags */
	m->cols[m->read_id].flags = from_my_24(&m->buf[i]);
	i += 2;
	fprintf(stderr, "flags: {");
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
	fprintf(stderr, "}\n");

	/* decimals */
	m->cols[m->read_id].decimals = m->buf[i];
	fprintf(stderr, "decimals: %d\n", m->cols[m->read_id].decimals);
	i += 1;

	/* filler */
	i += 2;

	/* default */
	i += my_lcb(&m->buf[i], &size, &nul);
	i += size;

	fprintf(stderr, "-----------------------------\n");
}
int c = 0;
void my_response(int fd, void *arg) {
	struct my *m = arg;
	int i;

	/* read length */
	read(fd, m->buf, 4);

	/* decode */
	m->packet_length = from_my_24(&m->buf[0]);

	/* packet number */
	m->packet_number = m->buf[3];

	/* read data */
	read(fd, m->buf, m->packet_length);

	/* error */
	if ((unsigned char)m->buf[0] == 255) {
	
		/* defined mysql error */
		if (m->packet_length > 3) {

			/* read error code */
			m->errorcode = from_my_16(&m->buf[1]);

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
		m->warnings = from_my_16(&m->buf[1]);
		m->status = from_my_16(&m->buf[3]);
		if (m->qst == MY_READ_LINE) {
			if (c == 1)
				exit(0);
			else
				c++;
		}
	}

	/* success */
	else if ((unsigned char)m->buf[0] == 0) {

		/* affected rows (wireshark donne 1 octet, mais en affiche 2 ...) */
		m->affected_rows = from_my_16(&m->buf[1]);

		/* server status */
		m->status = from_my_16(&m->buf[3]);

		/* server status */
		m->warnings = from_my_16(&m->buf[5]);
	}

	/* read response ... 
	 *
	 * Result Set Packet           1-250 (first byte of Length-Coded Binary)
	 * Field Packet                1-250 ("")
	 * Row Data Packet             1-250 ("")
	 */
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
			my_read_value(m);
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
	m->packet_length = from_my_24(&m->buf[0]);

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
	m->threadid = from_my_32(&m->buf[i]);

	/* first part of salt */
	strncpy(m->salt, &m->buf[i+4], SCRAMBLE_LENGTH_323);
	i += 4 + SCRAMBLE_LENGTH_323 + 1;

	/* options */
	m->options = from_my_16(&m->buf[i]);

	/* charset */
	m->charset = m->buf[i+2];

	/* server status */
	m->status = from_my_16(&m->buf[i+3]);

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
	m.database = "nagios";
	if (argc == 2)
		m.query = argv[1];
	else
		m.query =
		    //"SELECT COUNT(*) FROM (\n"
		    "SELECT\n"
		    "  GROUP_CONCAT(\n"
		    "    DISTINCT sub.GROUPES\n"
		    "    ORDER BY sub.GROUPES\n"
		    "    DESC SEPARATOR \"|\"\n"
		    "  )                AS GROUPES,\n"
		    "  sub.MACHINES     AS MACHINES,\n"
		    "  sub.MACHINE_NAME AS MACHINE_NAME,\n"
		    "  sub.SERVICES     AS SERVICES,\n"
		    "  sub.STATUS       AS STATUS,\n"
		    "  sub.SVCID        AS SVCID,\n"
		    "  sub.LASTCHECK    AS LASTCHECK,\n"
		    "  sub.DURATION     AS DURATION,\n"
		    "  sub.TYPE         AS TYPE,\n"
		    "  sub.ACK          AS ACK,\n"
		    "  sub.DOWNTIME     AS DOWNTIME,\n"
		    "  sub.NOTIF        AS NOTIF\n"
		    "\n"
		    "FROM (\n"
		    "\n"
		    "  SELECT\n"
		    "    PFFF.name1                           AS GROUPES,\n"
		    "    C.alias                              AS MACHINES,\n"
		    "    C.display_name                       AS MACHINE_NAME,\n"
		    "    D.display_name                       AS SERVICES,\n"
		    "    E.current_state                      AS STATUS,\n"
		    "    E.servicestatus_id                   AS SVCID,\n"
		    "    E.problem_has_been_acknowledged      AS ACK,\n"
		    "    TIMEDIFF(NOW(), E.last_check)        AS LASTCHECK,\n"
		    "    TIMEDIFF(NOW(), E.last_state_change) AS DURATION,\n"
		    "    \"svc\"                              AS TYPE,\n"
		    "    E.scheduled_downtime_depth           AS DOWNTIME,\n"
		    "    E.notifications_enabled              AS NOTIF\n"
		    "  \n"
		    "  FROM\n"
		    "         nagios_hostgroups AS A\n"
		    "    INNER JOIN nagios_objects AS PFFF            ON A.hostgroup_object_id = PFFF.object_id\n"
		    "    INNER JOIN nagios_hostgroup_members AS B     ON A.hostgroup_id = B.hostgroup_id\n"
		    "    INNER JOIN nagios_hosts AS C                 ON B.host_object_id = C.host_object_id\n"
		    "    INNER JOIN nagios_hoststatus AS K            ON B.host_object_id = K.host_object_id\n"
		    "    INNER JOIN nagios_services AS D              ON C.host_object_id = D.host_object_id\n"
		    "    INNER JOIN nagios_servicestatus AS E         ON D.service_object_id = E.service_object_id\n"
		    "    INNER JOIN nagios_service_contactgroups AS F ON F.service_id = D.service_id\n"
		    "    INNER JOIN nagios_contactgroups As G         ON F.contactgroup_object_id = G.contactgroup_object_id\n"
		    "    INNER JOIN nagios_contactgroup_members AS H  ON H.contactgroup_id = G.contactgroup_id\n"
		    "    INNER JOIN nagios_contacts AS I              ON I.contact_object_id = H.contact_object_id\n"
		    "    INNER JOIN nagios_objects AS J               ON J.object_id = I.contact_object_id\n"
		    "  \n"
		    "  WHERE\n"
		    "    (\n"
		    "          PFFF.name1     LIKE \"%%\"\n"
		    "      OR  C.alias        LIKE \"%%\"\n"
		    "      OR  C.display_name LIKE \"%%\" \n"
		    "      OR  D.display_name LIKE \"%%\" \n"
		    "    )\n"
		    "    AND J.name1 = \"coss-exosec\"\n"
		    "    AND E.current_state IN (0,1,2,3)\n"
		    "    AND E.problem_has_been_acknowledged IN (0,1)\n"
		    "    AND K.problem_has_been_acknowledged IN (0,1)\n"
		    "    AND K.current_state != 1\n"
		    "  \n"
		    "  UNION\n"
		    "  \n"
		    "  SELECT\n"
		    "    PFFF.name1                           AS GROUPES,\n"
		    "    C.alias                              AS MACHINES,\n"
		    "    C.display_name                       AS MACHINE_NAME,\n"
		    "    \"--host--\"                         AS SERVICES,\n"
		    "    K.current_state                      AS STATUS,\n"
		    "    K.hoststatus_id                      AS SVCID,\n"
		    "    K.problem_has_been_acknowledged      AS ACK,\n"
		    "    TIMEDIFF(NOW(), K.last_check)        AS LASTCHECK,\n"
		    "    TIMEDIFF(NOW(), K.last_state_change) AS DURATION,\n"
		    "    \"host\"                             AS TYPE,\n"
		    "    K.scheduled_downtime_depth           AS DOWNTIME,\n"
		    "    K.notifications_enabled              AS NOTIF\n"
		    "  \n"
		    "  FROM\n"
		    "         nagios_hostgroups AS A\n"
		    "    INNER JOIN nagios_objects AS PFFF           ON A.hostgroup_object_id = PFFF.object_id\n"
		    "    INNER JOIN nagios_hostgroup_members AS B    ON A.hostgroup_id = B.hostgroup_id\n"
		    "    INNER JOIN nagios_hosts AS C                ON B.host_object_id = C.host_object_id\n"
		    "    INNER JOIN nagios_hoststatus AS K           ON B.host_object_id = K.host_object_id\n"
		    "    INNER JOIN nagios_host_contactgroups AS F   ON F.host_id = C.host_id\n"
		    "    INNER JOIN nagios_contactgroups As G        ON F.contactgroup_object_id = G.contactgroup_object_id\n"
		    "    INNER JOIN nagios_contactgroup_members AS H ON H.contactgroup_id = G.contactgroup_id\n"
		    "    INNER JOIN nagios_contacts AS I             ON I.contact_object_id = H.contact_object_id\n"
		    "    INNER JOIN nagios_objects AS J              ON J.object_id = I.contact_object_id\n"
		    "  \n"
		    "  WHERE\n"
		    "    (\n"
		    "          PFFF.name1     LIKE \"%%\"\n"
		    "      OR  C.alias        LIKE \"%%\"\n"
		    "      OR  C.display_name LIKE \"%%\" \n"
		    "      OR  \"--host--\"   LIKE \"%%\" \n"
		    "    )\n"
		    "    AND J.name1 = \"coss-exosec\"\n"
		    "    AND K.current_state IN (0,1,2)\n"
		    "    AND K.problem_has_been_acknowledged IN (0,1)\n"
		    "\n"
		    ") AS sub\n"
		    "\n"
		    "GROUP BY\n"
		    "  SVCID\n"
		    "\n"
		    "ORDER BY GROUPES, MACHINES, SERVICES\n"
			 "LIMIT 0,30\n"
		    //") AS sub2\n"
			 ;

		//m.query = "SELECT TIMEDIFF(NOW(), test.ze_date) AS DIFF, * FROM test;";
		//m.query = "SELECT COUNT(*) AS COUNT FROM test;";

	myfd = ev_socket_connect("127.0.0.1:3306");
	if (myfd < 0)
		exit(1);

	ev_poll_fd_set(myfd, EV_POLL_READ, my_async_connect, &m);

	ev_poll_poll(1);
}
