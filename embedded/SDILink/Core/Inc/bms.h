/*
 * bms.h
 *
 *  Created on: 2023. 5. 9.
 *      Author: khryu
 */

#ifndef INC_BMS_H_
#define INC_BMS_H_

#include "bms_pack.h"

void initBMS(BMS_PACK *pack);

void initPack(BMS_PACK *pack);

void initModule(BMS_MODULE *module);

void initCell(BMS_CELL *cell);

void readBMS(BMS_PACK *pack);

void readPack(BMS_PACK *pack);

void readModule(BMS_MODULE *module);

void readCell(BMS_CELL *cell);

#endif /* INC_BMS_H_ */
