#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <mysql/mysql.h>
#include <mysql/my_global.h>

#include "mysac_utils.h"
#include "mysac.h"

void mysac_decode_field(MYSAC *mysac, MYSQL_FIELD *col) {
	int i;
	int len;
	unsigned long size;
	char nul;
	char *wh;

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

	wh = mysac->read;

	i = 0;

	/* n (Length Coded String)   def */
	i += my_lcb(&mysac->read[i], &size, &nul);
	col->def_length = size;
	memmove(wh, &mysac->read[i], size);
	col->def = wh;
	col->def[size] = '\0';
	wh += size + 1;
	i += size;

	/* n (Length Coded String)    catalog */
	col->catalog_length = 0;
	col->catalog = "";
	/*
	i += my_lcb(&mysac->read[i], &size, &nul);
	col->catalog_length = size;
	memmove(wh, &mysac->read[i], size);
	col->catalog = wh;
	col->catalog[size] = '\0';
	wh += size + 1;
	i += size;
	*/

	/* n (Length Coded String)    db */
	i += my_lcb(&mysac->read[i], &size, &nul);
	col->db_length = size;
	memmove(wh, &mysac->read[i], size);
	col->db = wh;
	col->db[size] = '\0';
	wh += size + 1;
	i += size;

	/* n (Length Coded String)    table */
	i += my_lcb(&mysac->read[i], &size, &nul);
	col->table_length = size;
	memmove(wh, &mysac->read[i], size);
	col->table = wh;
	col->table[size] = '\0';
	wh += size + 1;
	i += size;

	/* n (Length Coded String)    org_table */
	i += my_lcb(&mysac->read[i], &size, &nul);
	col->org_table_length = size;
	memmove(wh, &mysac->read[i], size);
	col->org_table = wh;
	col->org_table[size] = '\0';
	wh += size + 1;
	i += size;

	/* n (Length Coded String)    name */
	i += my_lcb(&mysac->read[i], &size, &nul);
	col->name_length = size;
	memmove(wh, &mysac->read[i], size);
	col->name = wh;
	col->name[size] = '\0';
	wh += size + 1;
	i += size;

	/* n (Length Coded String)    org_name */
	i += my_lcb(&mysac->read[i], &size, &nul);
	col->org_name_length = size;
	memmove(wh, &mysac->read[i], size);
	col->org_name = wh;
	col->org_name[size] = '\0';
	wh += size + 1;
	i += size;

	/* (filler) */
	i += 1;

	/* charset */
	col->charsetnr = uint2korr(&mysac->read[i]);
	i += 2;

	/* length */
	col->length = uint4korr(&mysac->read[i]);
	i += 4;

	/* type */
	col->type = (unsigned char)mysac->read[i];
	i += 1;

	/* flags */
	col->flags = uint3korr(&mysac->read[i]);
	i += 2;

	/* decimals */
	col->decimals = mysac->read[i];
	i += 1;

	/* filler */
	i += 2;

	/* default */
	i += my_lcb(&mysac->read[i], &size, &nul);
	i += size;

	/* set write pointer */
	mysac->read = wh;
}
