/*
 * bms_to_json.h
 *
 *  Created on: 2023. 5. 10.
 *      Author: khryu
 */

#ifndef INC_BMS_TO_JSON_H_
#define INC_BMS_TO_JSON_H_

#include "cJSON.h"
#include "bms.h"

cJSON* makeJsonObjectFromCell(BMS_CELL *cell);

cJSON* makeJsonObjectFromModule( BMS_MODULE *module);

cJSON* makeJsonObjectFromPack(BMS_PACK *pack);

char* getJsonStringFromBMS(BMS_PACK *pack);

char* getJsonStringFromBMSModule(BMS_MODULE *module);

#endif /* INC_BMS_TO_JSON_H_ */
