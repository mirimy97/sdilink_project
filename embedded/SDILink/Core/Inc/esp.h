/*
 * esp.h
 *
 *  Created on: 2023. 5. 9.
 *      Author: khryu
 */

#ifndef INC_ESP_H_
#define INC_ESP_H_

#include"stm32f1xx_hal.h"

int ESPSend(UART_HandleTypeDef *huart, char cmd[]);

int ESPReceive(UART_HandleTypeDef *huart, char target[]);

void ESPSendAT(UART_HandleTypeDef *huart);

void ESPSendAT_CWLAP(UART_HandleTypeDef *huart);

void ESPSendAT_CWJAP(UART_HandleTypeDef *huart);

void ESPSendAT_CWJAP_CHECK(UART_HandleTypeDef *huart);

int ESPSendAT_CIPSTART(UART_HandleTypeDef *huart);

int ESPSendAT_CIPSEND(UART_HandleTypeDef *huart, char cmd[]);

void ESPSendAT_CIPCLOSE(UART_HandleTypeDef *huart);

void ESPSendAT_POST(UART_HandleTypeDef *huart, char body[]);

void ESPSendAT_GET(UART_HandleTypeDef *huart);


#endif /* INC_ESP_H_ */
