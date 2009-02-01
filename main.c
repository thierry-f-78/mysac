#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <events.h>
#include <arpa/inet.h>

#include "mysac.h"

struct my {
	MYSAC m;
	unsigned long stmt_id;
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

char *database;

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
	 //"LIMIT 0,30\n"
    //") AS sub2\n"
	 ;
const char *query;

enum a {
	CONNECT,
	SETDB,
	STMT,
	QUERY,
};

void mysac_main(int fd, void *arg) {
	struct my *my;
	MYSAC *m;
	MYSAC_ROW *r;
	int err, j, i;
	struct timeval avant;
	struct timeval apres;
	struct timeval display;
	
	my = arg;
	m = &my->m;

	switch ((enum a)my->state) {

	/**************************************************

	  connect state

	**************************************************/
	case CONNECT:
		err = mysac_connect(m);
		if (err != 0) break;
		fprintf(stderr, "connection / authentication sucessfull\n");

		/* prepare set db */
		mysac_set_database(m, database);
		my->state = SETDB;

	/**************************************************

	  set database

	**************************************************/
	case SETDB:
		err = mysac_send_database(m);
		if (err != 0) break;

		/* prepare query */
		my->state = STMT;
		err = mysac_set_stmt_prepare(m, query);
		if (err != 0) break;

	/**************************************************

	   prepare statement 

	**************************************************/ 
	case STMT:
		err = mysac_send_stmt_prepare(m, &my->stmt_id);
		if (err != 0) break;

		mysac_set_stmt_execute(m, my->stmt_id);
		my->state = QUERY;

	/**************************************************

	  send query

	**************************************************/
	case_QUERY:
	case QUERY:
		gettimeofday(&avant, NULL);

		err = mysac_send_stmt_execute(m);
		if (err != 0) break;

#if 1
		fprintf(stderr, "request return ok\n");
		fprintf(stderr, "%d lines\n", mysac_num_rows(m->res));

		i = 0;
		while (1) {	
			struct tm *_tm;
			char toto[1024];
			MYSQL_FIELD *mf;
	
			/* get line */
			r = mysac_fetch_row(m->res);
			if (r == NULL)
				break;

			/* display line */
			fprintf(stderr, "%d: ", i);
			for (j=0; j<mysac_field_count(m->res); j++) {

				mf = &m->res->cols[j];
				fprintf(stderr, "%s\t%s\t", mf->name, mysac_type[mf->type]);

				switch (mf->type) {
	
				/* read blob */
				case MYSQL_TYPE_TINY_BLOB:
				case MYSQL_TYPE_MEDIUM_BLOB:
				case MYSQL_TYPE_LONG_BLOB:
				case MYSQL_TYPE_BLOB:
				/* eviter d'utiliser ce type a la con ! (enfin, aml defini quoi ...
				   il sert peut etre pour les very very bit int (clé de chiffrement */
				case MYSQL_TYPE_NEWDECIMAL:
				/* .... */
				case MYSQL_TYPE_BIT:
				/* read text */
				case MYSQL_TYPE_STRING:
				case MYSQL_TYPE_VAR_STRING:
					fprintf(stderr, "(%p) [", m->res->cr->data[j].string);
					fwrite(m->res->cr->data[j].string, 1, m->res->cr->lengths[j], stderr);
					fprintf(stderr, "]\n");
					break;
		
				case MYSQL_TYPE_TINY:
					fprintf(stderr, "%d\n", m->res->cr->data[j].stiny);
					break;
		
				case MYSQL_TYPE_SHORT:
					fprintf(stderr, "%d\n", m->res->cr->data[j].ssmall);
					break;
		
				case MYSQL_TYPE_INT24:
				case MYSQL_TYPE_LONG:
					fprintf(stderr, "%ld\n", m->res->cr->data[j].sint);
					break;
		
				case MYSQL_TYPE_LONGLONG:
					fprintf(stderr, "%lld\n", m->res->cr->data[j].sbigint);
					break;
		
				case MYSQL_TYPE_FLOAT:
					fprintf(stderr, "%f\n", m->res->cr->data[j].mfloat);
					break;
		
				case MYSQL_TYPE_DOUBLE:
					fprintf(stderr, "%f\n", m->res->cr->data[j].mdouble);
					break;
		
				case MYSQL_TYPE_TIME:
					fprintf(stderr, "%d.%06d\n", m->res->cr->data[j].tv.tv_sec,
					                             m->res->cr->data[j].tv.tv_usec);
					break;
		
				case MYSQL_TYPE_YEAR:
				case MYSQL_TYPE_TIMESTAMP:
				case MYSQL_TYPE_DATETIME:
				case MYSQL_TYPE_DATE:
					strftime(toto, 1024, "%Y-%m-%d %H:%M:%S",
					         m->res->cr->data[j].tm);
					fprintf(stderr, "%s\n", toto);
					break;
		
				case MYSQL_TYPE_NULL:
				case MYSQL_TYPE_DECIMAL:
				case MYSQL_TYPE_NEWDATE:
				case MYSQL_TYPE_VARCHAR:
				case MYSQL_TYPE_ENUM:
				case MYSQL_TYPE_SET:
				case MYSQL_TYPE_GEOMETRY:
					break;
				}
			}
			i++;
		}
#endif

		gettimeofday(&apres, NULL);
		display.tv_sec = apres.tv_sec - avant.tv_sec;
		display.tv_usec = apres.tv_usec - avant.tv_usec;
		if (display.tv_usec < 0) {
			display.tv_usec += 1000000;
			display.tv_sec --;
		}
		fprintf(stderr, "%d.%06d\n", display.tv_sec, display.tv_usec);

		// err = mysac_set_query(m, big_query);
		err = mysac_set_stmt_execute(m, my->stmt_id);;
		if (err != 0) break;
//		goto case_QUERY;

		exit(0);
	}

	/**************************************************

	  return code

	**************************************************/

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
		fprintf(stderr, "error(%d): %s %s\n", err, mysac_error(m), m->mysql_error);
		exit (1);
	}
}

int main(int argc, char *argv[]) {
	struct ev_timeout_basic_node tmout;
	struct my my;
	MYSAC *m;

	if (argc == 2)
		query = argv[1];

	else
//		query = "CALL search()";
//		query = big_query;
		query = "SELECT * FROM toto"; /* retourne tous les types */
//		query = "SELECT TIMEDIFF(NOW(), test.ze_date) AS DIFF FROM test";
//		query = "SELECT COUNT(*) AS COUNT FROM test;";

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
	mysac_setup(m, "127.0.0.1:3306", "root", "root", NULL, 0);

	// database = "nagios";
	database = "tests";
	mysac_connect(m);

	/* call connect */
	mysac_main(-1, &my);

	/* schedule read */
	ev_poll_poll(1);



}
