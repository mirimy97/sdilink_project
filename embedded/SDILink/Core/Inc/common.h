/*
 * common.h
 *
 *  Created on: 2023. 5. 9.
 *      Author: khryu
 */

#ifndef INC_COMMON_H_
#define INC_COMMON_H_

char* substr(const char *src, int m, int n);

int isContain(char src[], char target[]);

float getRandomValue(float min, float max);

void optimizeString(char *src, char **des);

#endif /* INC_COMMON_H_ */
