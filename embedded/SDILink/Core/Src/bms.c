/*
 * bms.c
 *
 *  Created on: 2023. 5. 9.
 *      Author: khryu
 */

#include <time.h>
#include <string.h>
#include <stdio.h>
#include "bms.h"
#include "common.h"

const int NUM_MODULES = 8;
const int NUM_CELLS = 12;

typedef enum
{
  BMS_CAR_UNKNOWN = 0,
  BMS_CAR_IDLE = 1,
  BMS_CAR_DRIVING = 2
} BMS_CAR_STATUS;


// BMS 초기화
void initBMS(BMS_PACK *pack)
{
	// Init Component && Setting Serial Code
	const int base = 10000;

	initPack(pack);
	strcpy(pack->serialCode, "SN-P10001");
	for(int i = 0; i < pack->numModules; ++i)
	{
		BMS_MODULE *module = &(pack->modules[i]);
		initModule(module);
		char moduleNumber[6];
		sprintf(moduleNumber, "%d", base + i + 1);
		strcpy(module->serialCode, "SN-M");
		strcat(module->serialCode, moduleNumber);
		for(int j = 0; j < module->numCells; ++j)
		{
			char cellNumber[6];
			BMS_CELL *cell = &(module->cell[j]);
			initCell(cell);
			sprintf(cellNumber, "%d", (base + (i * NUM_CELL) + j + 1));
			strcpy(cell->serialCode, "SN-C");
			strcat(cell->serialCode, cellNumber);
		}
	}
}

// Pack 정보 초기화
void initPack(BMS_PACK *pack)
{
	pack->numModules = NUM_MODULES;
	pack->capacity = 0;
	pack->cycle = 0;
	pack->status = BMS_CAR_DRIVING;
	pack->current = 0;
	pack->temperature = 0;
	pack->voltage = 0;
}

// Module 정보 초기화
void initModule(BMS_MODULE *module)
{
	module->numCells = NUM_CELLS;
	module->temperature = 0;
	module->voltage = 0;
}

// Cell 정보 초기화
void initCell(BMS_CELL *cell)
{
	cell->voltage = 0;
}

// BMS 정보 Read
void readBMS(BMS_PACK *pack)
{
	for(int i = 0; i < pack->numModules; ++i)
	{
		BMS_MODULE *module = &(pack->modules[i]);
		for(int j = 0; j < module->numCells; ++j)
		{
			BMS_CELL *cell = &(module->cell[j]);
			readCell(cell);
		}
		readModule(module);
	}
	readPack(pack);
}

void readPack(BMS_PACK *pack)
{

}

void readModule(BMS_MODULE *module)
{
	module->temperature = getRandomValue(50, 60);
	for(int i=0; i<module->numCells; ++i)
		module->voltage += module->cell[i].voltage;
}

void readCell(BMS_CELL *cell)
{
	cell->voltage = getRandomValue(2.5, 4.5);
}
