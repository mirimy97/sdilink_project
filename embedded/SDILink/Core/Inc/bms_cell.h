/*
 * bms_cell.h
 *
 *  Created on: Apr 27, 2023
 *      Author: SSAFY
 */

#ifndef INC_BMS_CELL_H_
#define INC_BMS_CELL_H_

typedef struct{
	float voltage;	// 셀의 전압
	char serialCode[10];	// 일련번호
} BMS_CELL;


#endif /* INC_BMS_CELL_H_ */
