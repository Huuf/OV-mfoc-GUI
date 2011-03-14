#include "OVStations.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

#pragma comment(lib, "sqlite3.lib")

void GetStationInfo(char *databaseFile, unsigned int company, unsigned int station, char *out) {
	sqlite3* db;
	char* db_err;
	char sqlComm[100];
	int result;

	sprintf(out, "Unknown: %u", station);

	sqlite3_open(databaseFile, &db);

	sprintf(sqlComm, "SELECT longname FROM stations_data WHERE company='%i' AND ovcid='%i'", company, station);
	sqlite3_stmt *statement;
	if (sqlite3_prepare_v2(db, sqlComm, -1, &statement, 0) == SQLITE_OK) {
		result = sqlite3_step(statement);
		if (result == SQLITE_ROW) {
			sprintf(out, "%s", sqlite3_column_text(statement, 0));
		}
	}
	sqlite3_finalize(statement);
	sqlite3_close(db);
}