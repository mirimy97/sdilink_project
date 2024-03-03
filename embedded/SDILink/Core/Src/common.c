/*
 * common.c
 *
 *  Created on: 2023. 5. 9.
 *      Author: SSAFY
 */

#include "common.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// 문자열  src에서 [m,n) 구간의 문자를 반환.
char* substr(const char *src, int m, int n)
{
    int len = n - m;
    char *dest = (char*)malloc(sizeof(char) * (len + 1));

    for (int i = m; i < n && (*(src + i) != '\0'); i++)
    {
        *dest = *(src + i);
        dest++;
    }

    *dest = '\0';
    return dest - len;
}

// 문자열  src에서 문자열 target이 포함되어 있는지 반환.
int isContain(char resp[], char target[]){
	int len = strlen(resp);
	int tlen = strlen(target);
	int result = 0;
	if(len<tlen)
		result = 0;
	else{
		for(int i=0; i<len-tlen; ++i){
			char* stateWord = substr(resp, i, i+tlen);
			if(!strcmp(stateWord,target)){
				result = 1;
				break;
			}
		}
	}
	return result;
}

// min이상, max미만의 임의의 float value 반환
float getRandomValue(float min, float max)
{
	float random = ((float) rand()) / (float) __RAND_MAX;
	float r = random * (max - min);

	return min + r;
}

// 문자열 최적화
void optimizeString(char *src, char **des)
{
	int totalLen = strlen(src);

	int count = 0;
	int len = strlen(src);
	for(int i = 0; i < len; ++i)
	{
		if(src[i] == '\r' || src[i] =='\n' || src[i] =='\t' || src[i] ==' ')
			count++;
	}

	*des = (char*)malloc(sizeof(char) * (totalLen - count + 1));

	int j = 0;
	for(int i = 0; i < len; ++i)
	{
		if(src[i] != '\r' && src[i] !='\n' && src[i] !='\t' && src[i] !=' ')
			(*des)[j++] = src[i];
	}
	(*des)[j] = '\0';
}
