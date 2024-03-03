/*
 * bms_module.h
 *
 *  Created on: Apr 27, 2023
 *      Author: SSAFY
 */

#ifndef INC_BMS_MODULE_H_
#define INC_BMS_MODULE_H_

#define NUM_CELL 12
#include "bms_cell.h"

typedef struct{
	int numCells;
	float voltage;	// 전압
	float temperature;	// 온도
	char serialCode[10];	// 일련번호
	BMS_CELL cell[NUM_CELL];
}BMS_MODULE ;


#endif /* INC_BMS_MODULE_H_ */
