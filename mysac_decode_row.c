#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <mysql/mysql.h>
#include <mysql/my_global.h>

#include "mysac.h"
#include "list.h"
#include "mysac_utils.h"





/**************************************************

   read data in binary type 

**************************************************/ 
int mysac_decode_binary_row(char *buf, int packet_len, MYSAC_RES *res, MYSAC_ROWS *row) {
	int j;
	int i;
	char nul;
	int year, month, day, hour, minut, second;
	unsigned long len;
	int tmp_len;
	unsigned char *packet;
	char *wh;
	uint32_t days;
	char _null_ptr[16];
	char *null_ptr;
	char bit;

	wh = buf;
	memcpy(_null_ptr, buf, 16);
	null_ptr = _null_ptr;
	bit = 4; /* first 2 bits are reserved */

	/* skip null bits */
	i = ( (res->nb_cols + 9) / 8 ) + 1;
	if (i > packet_len)
		return -1;

	for (j = 0; j < res->nb_cols; j++) {

		/*
		   We should set both row_ptr and is_null to be able to see
		   nulls in mysql_stmt_fetch_column. This is because is_null may point
		   to user data which can be overwritten between mysql_stmt_fetch and
		   mysql_stmt_fetch_column, and in this case nullness of column will be
		   lost. See mysql_stmt_fetch_column for details.
		 */
		if ( (*null_ptr & bit) != 0 ) {
			/* do nothing */
		}

		else {
			switch (res->cols[j].type) {
	
			/* read null */
			case MYSQL_TYPE_NULL:
				row->data[j].blob = NULL;
	
			/* read blob */
			case MYSQL_TYPE_TINY_BLOB:
			case MYSQL_TYPE_MEDIUM_BLOB:
			case MYSQL_TYPE_LONG_BLOB:
			case MYSQL_TYPE_BLOB:
			/* decimal ? maybe for very big num ... crypto key ? */
			case MYSQL_TYPE_DECIMAL:
			case MYSQL_TYPE_NEWDECIMAL:
			/* .... */
			case MYSQL_TYPE_BIT:
			/* read text */
			case MYSQL_TYPE_STRING:
			case MYSQL_TYPE_VAR_STRING:
			case MYSQL_TYPE_VARCHAR:
			/* read date */
			case MYSQL_TYPE_NEWDATE:
				tmp_len = my_lcb(&buf[i], &len, &nul, packet_len-i);
				if (tmp_len == -1)
					return -1;
				i += tmp_len;
				if (i + len > packet_len)
					return -1;
				if (nul == 1)
					row->data[j].blob = NULL;
				else {
					memmove(wh, &buf[i], len);
					row->data[j].blob = wh;
					row->data[j].blob[len] = '\0';
					i += len;
					wh += len + 1;
				}
				row->lengths[j] = len;
				break;
	
			case MYSQL_TYPE_TINY:
				if (i > packet_len - 1)
					return -1;
				row->data[j].stiny = buf[i];
				i++;
				break;
	
			case MYSQL_TYPE_SHORT:
				if (i > packet_len - 2)
					return -1;
				row->data[j].ssmall = sint2korr(&buf[i]);
				i += 2;
				break;
	
			case MYSQL_TYPE_INT24:
			case MYSQL_TYPE_LONG:
				if (i > packet_len - 4)
					return -1;
				row->data[j].sint = sint4korr(&buf[i]);
				i += 4;
				break;
	
			case MYSQL_TYPE_LONGLONG:
				if (i > packet_len - 8)
					return -1;
				row->data[j].sbigint = sint8korr(&buf[i]);
				i += 8;
				break;
	
			case MYSQL_TYPE_FLOAT:
				if (i > packet_len - 4)
					return -1;
				float4get(row->data[j].mfloat, &buf[i]);
				i += 4;
				break;
	
			case MYSQL_TYPE_DOUBLE:
				if (i > packet_len - 8)
					return -1;
				float8get(row->data[j].mdouble, &buf[i]);
				i += 8;
				break;
	
			/* libmysql/libmysql.c:3370
			 * static void read_binary_time(MYSQL_TIME *tm, uchar **pos) */
			case MYSQL_TYPE_TIME:
				tmp_len = my_lcb(&buf[i], &len, &nul, packet_len-i);
				if (tmp_len == -1)
					return -1;
				i += tmp_len;
				if (i + len > packet_len)
					return -1;
				if (nul == 1)
					row->data[j].blob = NULL;
	
				if (len > 0) {
					row->data[j].tv.tv_sec = 
					              ( uint4korr(&buf[i+1]) * 86400 ) +
					              ( buf[i+5] * 3600 ) +
					              ( buf[i+6] * 60 ) +
					                buf[i+7];
					if (buf[i] != 0)
						row->data[j].tv.tv_sec = - row->data[j].tv.tv_sec;
					if (len > 8)
						row->data[j].tv.tv_usec = uint4korr(&buf[i+8]);
					else
						row->data[j].tv.tv_usec = 0;
				}
				i += len;
				break;
	
			case MYSQL_TYPE_YEAR:
				row->data[j].tm->tm_year = uint2korr(&buf[i]) - 1900;
				row->data[j].tm->tm_mon  = 0;
				row->data[j].tm->tm_mday = 1;
				row->data[j].tm->tm_hour = 0;
				row->data[j].tm->tm_min  = 0;
				row->data[j].tm->tm_sec  = 0;
				i += 2;
				break;
	
			/* libmysql/libmysql.c:3400
			 * static void read_binary_datetime(MYSQL_TIME *tm, uchar **pos) */
			case MYSQL_TYPE_TIMESTAMP:
			case MYSQL_TYPE_DATETIME:
				tmp_len = my_lcb(&buf[i], &len, &nul, packet_len-i);
				if (tmp_len == -1)
					return -1;
				i += tmp_len;
				if (i + len > packet_len)
					return -1;
				if (nul == 1)
					row->data[j].blob = NULL;
	
				row->data[j].tm->tm_year = uint2korr(&buf[i+0]) - 1900;
				row->data[j].tm->tm_mon  = buf[i+2] - 1;
				row->data[j].tm->tm_mday = buf[i+3];
				if (len > 4) {
					row->data[j].tm->tm_hour = buf[i+4];
					row->data[j].tm->tm_min  = buf[i+5];
					row->data[j].tm->tm_sec  = buf[i+6];
				} else {
					row->data[j].tm->tm_hour = 0;
					row->data[j].tm->tm_min  = 0;
					row->data[j].tm->tm_sec  = 0;
				}
				if (len > 7) {
					/* les microsecondes ... */
				}
				i += len;
				break;
	
			/* libmysql/libmysql.c:3430
			 * static void read_binary_date(MYSQL_TIME *tm, uchar **pos) */
			case MYSQL_TYPE_DATE:
				tmp_len = my_lcb(&buf[i], &len, &nul, packet_len-i);
				if (tmp_len == -1)
					return -1;
				i += tmp_len;
				if (i + len > packet_len)
					return -1;
				if (nul == 1)
					row->data[j].blob = NULL;
	
				row->data[j].tm->tm_year = uint2korr(&buf[i+0]) - 1900;
				row->data[j].tm->tm_mon  = buf[i+2] - 1;
				row->data[j].tm->tm_mday = buf[i+3];
				row->data[j].tm->tm_hour = 0;
				row->data[j].tm->tm_min  = 0;
				row->data[j].tm->tm_sec  = 0;
				i += len;
				break;
	
			case MYSQL_TYPE_ENUM:
			case MYSQL_TYPE_SET:
			case MYSQL_TYPE_GEOMETRY:
				break;
			}
		}

		/* To next bit */
		bit <<= 1;

		/* To next byte */
		if ( (bit & 255) == 0 ) {
			bit = 1;
			null_ptr++;
		}
	}

	/*
	fprintf(stderr, "l=%d,  col=%d, i=%d size=%d buf=%p read=%p\n",
	                res->nb_lines, res->nb_cols, i,
	                buf_len, &mysac->buf, buf);
	*/
	return buf - wh;
}

/**************************************************

   read data in string type 

**************************************************/ 
int mysac_decode_string_row(char *buf, int len, MYSAC_RES *res, MYSAC_ROWS *row) {

#if 0
	for (j = 0; j < mysac->nb_cols; j++) {

		i += my_lcb(&buf[i], &mysac->cr->lengths[j],  &nul);

		if (nul == 1)
			mysac->cr->data[j] = NULL;
	
		else {
			switch (mysac->cols[j].mf.type) {
			case MYSQL_TYPE_SHORT:
			case MYSQL_TYPE_LONG:
				c = buf[i + mysac->cr->lengths[j]];
				buf[i + mysac->cr->lengths[j]] = '\0';
				mysac->cr->data[j] = (char *)atoi(&buf[i]);
				buf[i + mysac->cr->lengths[j]] = c;
				break;

			default:
				mysac->cr->data[j] = &buf[i];
				i += mysac->cr->lengths[j];
				break;
			}
		}
	}

	/* set 0 */
	mysac->nb_lines++;

	for (j = 0; j < mysac->nb_cols; j++) {
		switch (mysac->cols[j].mf.type) {
		case MYSQL_TYPE_BLOB:
		case MYSQL_TYPE_VAR_STRING:
			if (mysac->cr->data[j] != NULL)
				mysac->cr->data[j][mysac->cr->lengths[j]] = '\0';
			break;
		}
	}
}
	
/* next line */
buf += i + 1;
goto case_MYSAC_RECV_QUERY_DATA;
	}
	#endif
}

