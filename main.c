#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <events.h>
#include <arpa/inet.h>

#include "mysac.h"

struct my {
	MYSAC m;
	int state;
};

/*
  (Result Set Header Packet)  the number of columns
  (Field Packets)             column descriptors
  (EOF Packet)                marker: end of Field Packets
  (Row Data Packets)          row contents
  (EOF Packet)                marker: end of Data Packets
*/

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

const char big_query[] =
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

#if 0
void my_response(int fd, void *arg);
void my_auth_response(int fd, void *arg);
void my_select_db_response(int fd, void *arg);
void my_query_response(int fd, void *arg);

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

	/* re-init eof */
	m->eof = 1;

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
		m->eof = 1;
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
	struct my *m = arg;

	my_response(fd, m);

	/*
	  By sending this very specific reply server asks us to send scrambled
	  password in old format.
	*/
	if (m->packet_length == 1 && m->eof == 1 && 
	    m->options & CLIENT_SECURE_CONNECTION) {
		ev_poll_fd_clr(fd, EV_POLL_READ);
		ev_poll_fd_set(fd, EV_POLL_WRITE, my_auth2, arg);
	}

	/* if no error, continue program */
	else {
		ev_poll_fd_clr(fd, EV_POLL_READ);
		ev_poll_fd_set(fd, EV_POLL_WRITE, my_select_database, arg);
	}
}

void my_select_db_response(int fd, void *arg) {
	my_response(fd, arg);
	ev_poll_fd_clr(fd, EV_POLL_READ);
	ev_poll_fd_set(fd, EV_POLL_WRITE, my_send_query, arg);
}

void my_query_response(int fd, void *arg) {
	my_response(fd, arg);
}

#endif

enum a {
	CONNECT,
	SETDB,
	QUERY,
};

void mysac_main(int fd, void *arg) {
	struct my *my;
	MYSAC *m;
	int err;
	
	my = arg;
	m = &my->m;

	switch ((enum a)my->state) {

	/* connect state */
	case CONNECT:
		err = mysac_connect(m);
		if (err != 0) break;
		fprintf(stderr, "connection / authentication sucessfull\n");

		/* prepare set db */
		//mysac_set_database(m, "tests");
		mysac_set_database(m, "nagios");
		my->state = SETDB;

	/* set database */
	case SETDB:
		err = mysac_send_database(m);
		if (err != 0) break;
		fprintf(stderr, "database send\n");

		/* preapare query */
		my->state = QUERY;
		// err = mysac_set_query(m, "SELECT COUNT(*) AS COUNT FROM test");
		err = mysac_set_query(m, big_query);
		if (err != 0) break;
	
	/* send query */
	case QUERY:
		err = mysac_send_query(m);
		if (err != 0) break;
		fprintf(stderr, "request sended\n");
		exit(9);
	}

	/* want read */
	if (err == MYSAC_WANT_READ) {
		ev_poll_fd_clr(mysac_get_fd(m), EV_POLL_WRITE);
		ev_poll_fd_set(mysac_get_fd(m), EV_POLL_READ, mysac_main, my);
	}

	/* want write */
	else if (err == MYSAC_WANT_WRITE) {
		ev_poll_fd_clr(mysac_get_fd(m), EV_POLL_READ);
		ev_poll_fd_set(mysac_get_fd(m), EV_POLL_WRITE, mysac_main, my);
	}

	/* error */
	else if (err != 0) {
		fprintf(stderr, "error(%d): %s\n", err, mysac_error(m));
		exit (1);
	}
}

int main(int argc, char *argv[]) {
	struct ev_timeout_basic_node tmout;
	struct my my;
	MYSAC *m;

	/* init sheduling */
	poll_select_register();
	ev_timeout_init(&tmout);
	ev_poll_init(100, &tmout);

	/* init mysql */
	my.state = CONNECT;
	m = &my.m;
	mysac_init(m);

	//mysac_setup(m, "127.0.0.1:4000", "hypervisor", "PuuQuae6", "nagios", 0);
	//mysac_setup(m, "127.0.0.1:3306", "root", "root", "nagios", 0);
	mysac_setup(m, "127.0.0.1:3306", "root", "root", "test", 0);
	mysac_connect(m);

	/* call connect */
	mysac_main(-1, &my);

	/* schedule read */
	ev_poll_poll(1);


	/*
	if (argc == 2)
		m->query = argv[1];
	else
		*/
		//m.query = "SELECT TIMEDIFF(NOW(), test.ze_date) AS DIFF, * FROM test;";
		//m.query = "SELECT COUNT(*) AS COUNT FROM test;";

}
