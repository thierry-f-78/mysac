#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <mysql/mysql.h>
#include <mysql/my_global.h>

#include "mysac_decode_paquet.h"
#include "mysac.h"
#include "list.h"
#include "mysac_utils.h"





/**************************************************

   read data in binary type 

**************************************************/ 
void mysac_decode_binary_row(MYSAC *mysac) {
	int j;
	int i;
	char nul;
	int year, month, day, hour, minut, second;
	unsigned long len;
	unsigned char *packet;
	char *wh;
	uint32_t days;
	char _null_ptr[16];
	char *null_ptr;
	char bit;

	wh = mysac->read;
	memcpy(_null_ptr, mysac->read, 16);
	null_ptr = _null_ptr;
	bit = 4; /* first 2 bits are reserved */

	/* skip null bits */
	i = ( (mysac->res->nb_cols + 9) / 8 ) + 1;

	for (j = 0; j < mysac->res->nb_cols; j++) {

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
			switch (mysac->res->cols[j].type) {
	
			/* read null */
			case MYSQL_TYPE_NULL:
				mysac->res->cr->data[j].blob = NULL;
	
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
				i += my_lcb(&mysac->read[i], &len,  &nul);
				if (nul == 1)
					mysac->res->cr->data[j].blob = NULL;
				else {
					memmove(wh, &mysac->read[i], len);
					mysac->res->cr->data[j].blob = wh;
					mysac->res->cr->data[j].blob[len] = '\0';
					i += len;
					wh += len + 1;
				}
				mysac->res->cr->lengths[j] = len;
				break;
	
			case MYSQL_TYPE_TINY:
				mysac->res->cr->data[j].stiny = mysac->read[i];
				i++;
				break;
	
			case MYSQL_TYPE_SHORT:
				mysac->res->cr->data[j].ssmall = sint2korr(&mysac->read[i]);
				i += 2;
				break;
	
			case MYSQL_TYPE_INT24:
			case MYSQL_TYPE_LONG:
				mysac->res->cr->data[j].sint = sint4korr(&mysac->read[i]);
				i += 4;
				break;
	
			case MYSQL_TYPE_LONGLONG:
				mysac->res->cr->data[j].sbigint = sint8korr(&mysac->read[i]);
				i += 8;
				break;
	
			case MYSQL_TYPE_FLOAT:
				float4get(mysac->res->cr->data[j].mfloat, &mysac->read[i]);
				i += 4;
				break;
	
			case MYSQL_TYPE_DOUBLE:
				float8get(mysac->res->cr->data[j].mdouble, &mysac->read[i]);
				i += 8;
				break;
	
			/* libmysql/libmysql.c:3370
			 * static void read_binary_time(MYSQL_TIME *tm, uchar **pos) */
			case MYSQL_TYPE_TIME:
				packet = &mysac->read[i];
				len = net_field_length(&packet);
				i += (int) ( (char *)packet - (char *)&mysac->read[i] );
	
				if (len > 0) {
					mysac->res->cr->data[j].tv.tv_sec = 
					              ( uint4korr(&mysac->read[i+1]) * 86400 ) +
					              ( mysac->read[i+5] * 3600 ) +
					              ( mysac->read[i+6] * 60 ) +
					                mysac->read[i+7];
					if (mysac->read[i] != 0)
						mysac->res->cr->data[j].tv.tv_sec = 
						                          - mysac->res->cr->data[j].tv.tv_sec;
					if (len > 8)
						mysac->res->cr->data[j].tv.tv_usec =
						                                 uint4korr(&mysac->read[i+8]);
					else
						mysac->res->cr->data[j].tv.tv_usec = 0;
				}
				i += len;
				break;
	
			case MYSQL_TYPE_YEAR:
				mysac->res->cr->data[j].tm->tm_year =
				                                  uint2korr(&mysac->read[i]) - 1900;
				mysac->res->cr->data[j].tm->tm_mon  = 0;
				mysac->res->cr->data[j].tm->tm_mday = 1;
				mysac->res->cr->data[j].tm->tm_hour = 0;
				mysac->res->cr->data[j].tm->tm_min  = 0;
				mysac->res->cr->data[j].tm->tm_sec  = 0;
				i += 2;
				break;
	
			/* libmysql/libmysql.c:3400
			 * static void read_binary_datetime(MYSQL_TIME *tm, uchar **pos) */
			case MYSQL_TYPE_TIMESTAMP:
			case MYSQL_TYPE_DATETIME:
				packet = &mysac->read[i];
				len = net_field_length(&packet);
				i += (int) ( (char *)packet - (char *)&mysac->read[i] );
	
				mysac->res->cr->data[j].tm->tm_year = 
				                                uint2korr(&mysac->read[i+0]) - 1900;
				mysac->res->cr->data[j].tm->tm_mon  = mysac->read[i+2] - 1;
				mysac->res->cr->data[j].tm->tm_mday = mysac->read[i+3];
				if (len > 4) {
					mysac->res->cr->data[j].tm->tm_hour = mysac->read[i+4];
					mysac->res->cr->data[j].tm->tm_min  = mysac->read[i+5];
					mysac->res->cr->data[j].tm->tm_sec  = mysac->read[i+6];
				} else {
					mysac->res->cr->data[j].tm->tm_hour = 0;
					mysac->res->cr->data[j].tm->tm_min  = 0;
					mysac->res->cr->data[j].tm->tm_sec  = 0;
				}
				if (len > 7) {
					/* les microsecondes ... */
				}
				i += len;
				break;
	
			/* libmysql/libmysql.c:3430
			 * static void read_binary_date(MYSQL_TIME *tm, uchar **pos) */
			case MYSQL_TYPE_DATE:
				packet = &mysac->read[i];
				len = net_field_length(&packet);
				i += (int) ( (char *)packet - (char *)&mysac->read[i] );
	
				mysac->res->cr->data[j].tm->tm_year =
				                                uint2korr(&mysac->read[i+0]) - 1900;
				mysac->res->cr->data[j].tm->tm_mon  = mysac->read[i+2] - 1;
				mysac->res->cr->data[j].tm->tm_mday = mysac->read[i+3];
				mysac->res->cr->data[j].tm->tm_hour = 0;
				mysac->res->cr->data[j].tm->tm_min  = 0;
				mysac->res->cr->data[j].tm->tm_sec  = 0;
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

	mysac->read_len += &mysac->read[i] - wh;
	mysac->read = wh;
	fprintf(stderr, "l=%d,  col=%d, i=%d size=%d buf=%p read=%p\n",
	                mysac->res->nb_lines, mysac->res->nb_cols, i,
	                mysac->read_len, &mysac->buf, mysac->read);
}

/**************************************************

   read data in string type 

**************************************************/ 
int mysac_decode_string_row(MYSAC *mysac) {

#if 0
	for (j = 0; j < mysac->nb_cols; j++) {

		i += my_lcb(&mysac->read[i], &mysac->cr->lengths[j],  &nul);

		if (nul == 1)
			mysac->cr->data[j] = NULL;
	
		else {
			switch (mysac->cols[j].mf.type) {
			case MYSQL_TYPE_SHORT:
			case MYSQL_TYPE_LONG:
				c = mysac->read[i + mysac->cr->lengths[j]];
				mysac->read[i + mysac->cr->lengths[j]] = '\0';
				mysac->cr->data[j] = (char *)atoi(&mysac->read[i]);
				mysac->read[i + mysac->cr->lengths[j]] = c;
				break;

			default:
				mysac->cr->data[j] = &mysac->read[i];
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
mysac->read += i + 1;
goto case_MYSAC_RECV_QUERY_DATA;
	}
	#endif
}

