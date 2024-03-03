/*
 * esp.c
 *
 *  Created on: 2023. 5. 9.
 *      Author: khryu
 */

#include "esp.h"
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <stdbool.h>
#include "common.h"

// Define CONST VALUES
#define OK "OK"
#define CIPOK ">"
#define MAX_SIZE 1024

const int MAX_SEND_RETRY = 5;
const int MAX_RECEIVE_RETRY = 5;
const int TIME_OUT = 1000;
const int MAX_TIME_OUT = 3000;

// Server
#define HTTP_SERVER "192.168.30.175"
#define HTTP_PORT 8000
#define HTTP_API_PATH "/test"

// AT command
#define ESP_COMMAND_AT "AT\r\n"
#define ESP_COMMAND_AT_CWLAP "AT+CWLAP\r\n"
#define ESP_COMMAND_AT_CWJAP "AT+CWJAP=\"SSAFY_GUEST\",\"ssafy2023!\"\r\n"
#define ESP_COMMAND_AT_CWJAP_CHECK "AT+CWJAP?\r\n"
#define ESP_COMMAND_AT_CIPSTART "AT+CIPSTART=\"TCP\",\"%s\",%d\r\n"
#define ESP_COMMAND_AT_CIPSEND "AT+CIPSEND=%d\r\n"
#define ESP_COMMAND_AT_CIPCLOSE "AT+CIPCLOSE\r\n"
#define ESP_COMMAND_AT_POST "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s"
#define ESP_COMMAND_AT_GET "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"

// Variable
char response[MAX_SIZE];
char request[MAX_SIZE];

// ESP8266 모듈에 command를 전송
int ESPSend(UART_HandleTypeDef *huart, char cmd[])
{
	int count = 0;
	HAL_StatusTypeDef state;
	while(count<MAX_SEND_RETRY)
	{
		state = HAL_UART_Transmit(huart, (uint8_t*)cmd, strlen(cmd), TIME_OUT);
		if(HAL_OK == state)
		{
			return true;
		}
		if(HAL_TIMEOUT == state)
		{
			HAL_Delay(MAX_TIME_OUT);
		}
		count++;
	}
	return false;
}

// ESP8266 모듈에서 응답을 수신
// response에서 target문자열을 발견하면 성공으로 간주한다.
int ESPReceive(UART_HandleTypeDef *huart, char target[])
{
	int count = 0;
	HAL_StatusTypeDef state;
	while(count < MAX_RECEIVE_RETRY)
	{
		memset(response, 0 , MAX_SIZE);
		state = HAL_UART_Receive(huart, (uint8_t*)response, MAX_SIZE, TIME_OUT);
		if(HAL_OK == state)
		{
			return true;
		}
//		if(HAL_TIMEOUT == state)
//		{
//			HAL_Delay(MAX_TIME_OUT);
//		}
		if(true == isContain(response, target))
		{
			return true;
		}
		count++;
	}
	return false;
}

// ESP8266에 AT 명령어를 송신
void ESPSendAT(UART_HandleTypeDef *huart)
{
	printf("Send : %s ", ESP_COMMAND_AT);
	if(false == ESPSend(huart, ESP_COMMAND_AT))
	{
		printf("Send AT Fail\n");
		return;
	}

	if(false == ESPReceive(huart, OK))
	{
		printf("Receive Fail\n");
		return;
	}
	char *result = strchr(response, '\n');
	printf("Receive : %s\r\n", result+1);
}

// 사용할 수 있는 Access Point를 검색
void ESPSendAT_CWLAP(UART_HandleTypeDef *huart)
{
	printf("Send : %s ", ESP_COMMAND_AT_CWLAP);
	if(false == ESPSend(huart, ESP_COMMAND_AT_CWLAP))
	{
		printf("Send AT+CWLAP Fail\n");
		return;
	}

	if(false == ESPReceive(huart, OK))
	{
		printf("Receive Fail\n");
		return;
	}
	char *result = strchr(response, '\n');
	printf("Receive : %s\r\n", result+1);
}

// 특정 Access Point에 연결한다.
void ESPSendAT_CWJAP(UART_HandleTypeDef *huart)
{
	printf("Send : %s ", ESP_COMMAND_AT_CWJAP);
	if(false == ESPSend(huart, ESP_COMMAND_AT_CWJAP))
	{
		printf("Send AT+CWJAP Fail\n");
		return;
	}

	if(false == ESPReceive(huart, OK))
	{
		printf("Receive Fail\n");
		return;
	}
	char *result = strchr(response, '\n');
	printf("Receive : %s\r\n", result+1);
}

// 현재 연결되어 있는 Access Point의 정보를 출력한다.
void ESPSendAT_CWJAP_CHECK(UART_HandleTypeDef *huart)
{
	printf("Send : %s ", ESP_COMMAND_AT_CWJAP_CHECK);
	if(false == ESPSend(huart, ESP_COMMAND_AT_CWJAP_CHECK))
	{
		printf("Send AT+CWJAP? Fail\n");
		return;
	}

	if(false == ESPReceive(huart, OK))
	{
		printf("Receive Fail\n");
		return;
	}
	char *result = strchr(response, '\n');
	printf("Receive : %s\r\n", result+1);
}

// 서버와 TCP 연결을 한다. ( Purpose For Using HTTP Protocol )
int ESPSendAT_CIPSTART(UART_HandleTypeDef *huart)
{
	memset(request, 0, MAX_SIZE);
	sprintf(request, ESP_COMMAND_AT_CIPSTART, HTTP_SERVER, HTTP_PORT);
	printf("Send : %s ", request);
	if(false == ESPSend(huart, request))
	{
		printf("Send AT+CIPSTART Fail\n");
		return false;
	}

	if(false == ESPReceive(huart, OK))
	{
		printf("Receive Fail\n");
		return false;
	}
	char *result = strchr(response, '\n');
	printf("Receive : %s\r\n", result+1);
}

//
int ESPSendAT_CIPSEND(UART_HandleTypeDef *huart, char cmd[])
{
	return 0;
}

// 서버와 연결된 TCP Connection을 종료한다.
void ESPSendAT_CIPCLOSE(UART_HandleTypeDef *huart)
{
	printf("Send : %s ", ESP_COMMAND_AT_CIPCLOSE);
	if(false == ESPSend(huart, ESP_COMMAND_AT_CIPCLOSE))
	{
		printf("Send AT+CIPCLOSE Fail\n");
		return;
	}

	if(false == ESPReceive(huart, OK))
	{
		printf("Receive Fail\n");
		return;
	}
	char *result = strchr(response, '\n');
	printf("Receive : %s\r\n", result+1);
}

// Server에 POST 요청을 보낸다.
void ESPSendAT_POST(UART_HandleTypeDef *huart, char body[])
{
	memset(request, 0, MAX_SIZE);
	sprintf(request, ESP_COMMAND_AT_CIPSEND, (strlen(ESP_COMMAND_AT_POST) + strlen(HTTP_API_PATH) + strlen(HTTP_SERVER) + strlen(body) + 2));
	printf("Send : %s ", request);
	if(false == ESPSend(huart, request))
	{
		printf("Send AT+CIPSEND Fail\n");
		return;
	}

	if(false == ESPReceive(huart, CIPOK))
	{
		printf("Receive Fail\n");
		return;
	}
	char *result = strchr(response, '\n');
	printf("Receive : %s\r\n", result+1);

	HAL_Delay(MAX_TIME_OUT);
	memset(request, 0, MAX_SIZE);
	sprintf(request, ESP_COMMAND_AT_POST, HTTP_API_PATH, HTTP_SERVER, strlen(body), body);
	printf("Send : %s ", request);
	if(false == ESPSend(huart, request))
	{
		printf("Send POST Fail\n");
		return;
	}

	if(false == ESPReceive(huart, OK))
	{
		printf("Receive Fail\n");
		return;
	}
	result = strchr(response, '\n');
	printf("Receive : %s\r\n", result+1);
}

// Server에 GET 요청을 보낸다.
void ESPSendAT_GET(UART_HandleTypeDef *huart)
{
	memset(request, 0, MAX_SIZE);
	sprintf(request, ESP_COMMAND_AT_CIPSEND, (strlen(ESP_COMMAND_AT_GET) + strlen(HTTP_API_PATH) + strlen(HTTP_SERVER) + 2));
	printf("Send : %s ", request);
	if(false == ESPSend(huart, request))
	{
		printf("Send AT+CIPSEND Fail\n");
		return;
	}

	if(false == ESPReceive(huart, CIPOK))
	{
		printf("Receive Fail\n");
		return;
	}
	char *result = strchr(response, '\n');
	printf("Receive : %s\r\n", result+1);

	HAL_Delay(MAX_TIME_OUT);
	memset(request, 0, MAX_SIZE);
	sprintf(request, ESP_COMMAND_AT_GET, HTTP_API_PATH, HTTP_SERVER);
	printf("Send : %s ", request);
	if(false == ESPSend(huart, request))
	{
		printf("Send GET Fail\n");
		return;
	}

	if(false == ESPReceive(huart, OK))
	{
		printf("Receive Fail\n");
		return;
	}
	result = strchr(response, '\n');
	printf("Receive : %s\r\n", result+1);
}
