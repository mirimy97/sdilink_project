/*
 * bms_pack.h
 *
 *  Created on: Apr 27, 2023
 *      Author: khryu
 */

#ifndef INC_BMS_PACK_H_
#define INC_BMS_PACK_H_

#define NUM_MODULE 8
#include "bms_module.h"

typedef struct{
	int numModules;
	int capacity;	// 용량
	int cycle;	// 충전사이클
	float current;	// 전류
	float voltage;	// 전압
	float temperature;	// 온도
	char serialCode[10];	// 일련번호
	char status;	// 상태 ( 1.충전, 2.주행)
	BMS_MODULE modules[NUM_MODULE];
} BMS_PACK;


#endif /* INC_BMS_PACK_H_ */
