/*
 * bms_to_json.c
 *
 *  Created on: 2023. 5. 10.
 *      Author: khryu
 */

#include "bms_to_json.h"
#include "common.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

cJSON* makeJsonObjectFromCell(BMS_CELL *cell)
{
	cJSON *json = cJSON_CreateObject();
	cJSON_AddItemToObject(json, "serial", cJSON_CreateString(cell->serialCode));
	cJSON_AddItemToObject(json, "voltage", cJSON_CreateNumber(cell->voltage));
	return json;
}

cJSON* makeJsonObjectFromModule(BMS_MODULE *module)
{
	cJSON *json = cJSON_CreateObject();
	cJSON_AddItemToObject(json, "serial", cJSON_CreateString(module->serialCode));
	cJSON_AddItemToObject(json, "voltage", cJSON_CreateNumber(module->voltage));
	cJSON_AddItemToObject(json, "temperature", cJSON_CreateNumber(module->temperature));
	return json;
}

cJSON* makeJsonObjectFromPack(BMS_PACK *pack)
{
	cJSON *json = cJSON_CreateObject();
	cJSON_AddItemToObject(json, "serial", cJSON_CreateString(pack->serialCode));
	cJSON_AddItemToObject(json, "voltage", cJSON_CreateNumber(pack->voltage));
	cJSON_AddItemToObject(json, "temperature", cJSON_CreateNumber(pack->temperature));
	cJSON_AddItemToObject(json, "current", cJSON_CreateNumber(pack->current));
	cJSON_AddItemToObject(json, "capacity", cJSON_CreateNumber(pack->capacity));
	cJSON_AddItemToObject(json, "status", cJSON_CreateNumber(pack->status));
	cJSON_AddItemToObject(json, "cycle", cJSON_CreateNumber(pack->cycle));
	return json;
}

cJSON *cellJsonList;
cJSON *moduleJson;
cJSON *moduleJsonList;
cJSON *packJson;

char *moduleJsonString[8];
char *packJsonString;

char* getJsonStringFromBMS(BMS_PACK *pack)
{
	char *fullString;

	moduleJsonList = cJSON_CreateArray();
	for(int i = 0; i < pack->numModules; ++i)
	{
		BMS_MODULE *module = &(pack->modules[i]);

		cellJsonList = cJSON_CreateArray();
		for(int j = 0; j < module->numCells; ++j)
		{
			BMS_CELL *cell = &(module->cell[j]);

			// Make Cell Json
			cJSON_AddItemToArray(cellJsonList, makeJsonObjectFromCell(cell));
		}

		// Make Module Json
		moduleJson = makeJsonObjectFromModule(module);
		cJSON_AddItemToObject(moduleJson, "cells", cellJsonList);

		// optimize length
		fullString = cJSON_Print(moduleJson);
		optimizeString(fullString, &(moduleJsonString[i]));

		free(fullString);
		cJSON_Delete(moduleJson);

		cJSON_AddItemToArray(moduleJsonList, cJSON_CreateString("%s"));
	}

	packJson = makeJsonObjectFromPack(pack);
	cJSON_AddItemToObject(packJson, "modules", moduleJsonList);

	fullString = cJSON_Print(packJson);
	optimizeString(fullString, &packJsonString);

	int totalSize = strlen(packJsonString)+1;
	for(int i = 0; i < pack->numModules; ++i)
		totalSize += strlen(moduleJsonString[i]);

	char *resultString = (char*)malloc(sizeof(char) * (totalSize + 1));
	memset(resultString, 0, totalSize+1);

	sprintf(resultString, packJsonString,
			moduleJsonString[0],
			moduleJsonString[1],
			moduleJsonString[2],
			moduleJsonString[3],
			moduleJsonString[4],
			moduleJsonString[5],
			moduleJsonString[6],
			moduleJsonString[7]);
	for(int i = 0; i < pack->numModules; ++i)
		free(moduleJsonString[i]);
	free(packJsonString);
	free(fullString);
	cJSON_Delete(packJson);

	return resultString;
}

char* getJsonStringFromBMSModule(BMS_MODULE *module)
{
	cellJsonList = cJSON_CreateArray();
	for(int i = 0; i < module->numCells; ++i)
	{
		BMS_CELL *cell = &(module->cell[i]);

		// Make Cell Json
		cJSON_AddItemToArray(cellJsonList, makeJsonObjectFromCell(cell));
	}

	// Make Module Json
	moduleJson = makeJsonObjectFromModule(module);
	cJSON_AddItemToObject(moduleJson, "cells", cellJsonList);

	char *fullString = cJSON_Print(moduleJson);
	optimizeString(fullString, &(moduleJsonString[0]));
	cJSON_Delete(moduleJson);
	free(fullString);

	return moduleJsonString[0];
}
