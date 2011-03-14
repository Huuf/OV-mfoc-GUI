#pragma once
#include <stdio.h>

typedef struct {
	unsigned char valid;
	int location;
	unsigned int date;
	unsigned int time;
	unsigned int unknownConstant;
	unsigned int transfer;
	unsigned int company;
	unsigned int id;
	unsigned int station;
	unsigned int poleid;
	unsigned int vehicleId;
	unsigned int productId;
	unsigned int unknownConstant2;
	unsigned int amount;

}ov_data;

typedef struct {
	unsigned char valid;
	int location;
	char company;
	unsigned int id;
	unsigned int subscription;
	unsigned int validFrom;
	unsigned int validTo;
} ov_Subscription;

void GetDateSince1997(unsigned int days, char *out);
void GetCompanyName(unsigned int company, char *out);
void GetTransfer(unsigned int transfer, char *out);
void OvcClassicTransaction(unsigned char * buffer, int offset, int start, int length, ov_data *ovTrans);
void OvcSubscription(unsigned char * buffer, int offset, int start, int length, ov_Subscription *ovSubscription);
void GetSubscription(unsigned int company, unsigned int subscription, char *out);