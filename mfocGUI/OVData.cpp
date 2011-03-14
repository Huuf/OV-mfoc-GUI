#include "OVData.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

//Number of days in a month
int DaysInMonth[12] = {
	31, //Jan
	28, //feb
	31, //mar
	30, //apr
	31, //may
	30, //jun
	31, //jul
	31, //aug
	30, //sep
	31, //oct
	30, //nov
	31, //dec
};

//! Is the given year a leap year?
int is_leapyear(unsigned int year) {
	return (year % 4) ? 0 : (!(year % 400)) ? 1 : (!(year % 100)) ? 0 : 1;
}

//! Add days since 1997-1-1
void GetDateSince1997(unsigned int days, char *out) {
	unsigned int iYear = 1997;
	unsigned int iLeap = 0;
	unsigned int iMonth = 0;

	while (days >= 365 + iLeap) {
		days -= 365 + iLeap;
		iYear++;
		iLeap = is_leapyear(iYear);
	}

	while (days >= DaysInMonth[iMonth] + ((iMonth == 2 && iLeap)?1:0)) {
		days -= DaysInMonth[iMonth] + ((iMonth == 2 && iLeap)?1:0);
		iMonth++;
	}

	sprintf(out, "%04u-%02u-%02u", iYear, iMonth + 1, days + 1);
}

//! Get the company name
void GetCompanyName(unsigned int company, char *out) {
	switch (company) {
		case 0: sprintf(out, "TLS"); return;
		case 1: sprintf(out, "Connexxion"); return;
		case 2: sprintf(out, "GVB"); return;
		case 3: sprintf(out, "HTM"); return;
		case 4: sprintf(out, "NS"); return;
		case 5: sprintf(out, "RET"); return;
		case 7: sprintf(out, "Veolia"); return;
		case 8: sprintf(out, "Arriva"); return;
		case 9: sprintf(out, "Syntus"); return;
		case 12: sprintf(out, "DUO"); return;
		default: sprintf(out, "Unknown %i", company); return;
	}
}

//! Get the transfer action
void GetTransfer(unsigned int transfer, char *out) {
	switch (transfer) {
		case 0: sprintf(out, "purchase"); return;
		case 1: sprintf(out, "check-in"); return;
		case 2: sprintf(out, "check-out"); return;
		case 6: sprintf(out, "transfer"); return;
		case -2: sprintf(out, "credit"); return;
		case -3: sprintf(out, "no-data"); return;
		default: sprintf(out, "Unknown %i", transfer); return;
	}
}

unsigned int GetBitsFromBuffer(unsigned char * buffer, int iStartBit, int iLength) {
	int iEndBit = iStartBit + iLength - 1;
	int iSByte = iStartBit / 8;
  int iSBit = iStartBit % 8;
  int iEByte = iEndBit / 8;
  int iEBit = iEndBit % 8;
  if (iSByte == iEByte) {
    return (unsigned int)((buffer[iEByte] >> (7 - iEBit)) & (0xFF >> (8 - iLength)));
  }
  else {
    unsigned int uRet = ((buffer[iSByte] & (0xFF >> iSBit)) << (((iEByte - iSByte - 1) * 8) + (iEBit + 1)));
    for (int i = iSByte + 1; i < iEByte; i++) {
      uRet |= ((buffer[i] & 0xFF) << (((iEByte - i - 1) * 8) + (iEBit + 1)));
    }
    uRet |= (buffer[iEByte] >> (7 - iEBit));
    return uRet;
  }
}

void OvcSubscription(unsigned char * buffer, int offset, int start, int length, ov_Subscription *ovSubscription) {
	ovSubscription->valid = 1;
	ovSubscription->location = offset;
	ovSubscription->validFrom = 0;
	ovSubscription->validTo = 0;
	if (buffer[0] == 0x0a && buffer[1] == 0x00 && buffer[2] == 0xe0 && ((buffer[3] & 0xF0) == 0x00)) {
		ovSubscription->id = ((buffer[9] & 0xFF) << 4) | ((buffer[10] >> 4) & 0x0F);
		ovSubscription->company = ((buffer[4] >> 4) & 0x0F);
		ovSubscription->subscription = ((buffer[4] & 0x0F) << 12) | ((buffer[5] & 0xFF) << 4) | ((buffer[6] >> 4) & 0x0F);
		ovSubscription->validFrom = ((buffer[11] & 0x07) << 11) | ((buffer[12] & 0xFF) << 3) | ((buffer[13] >> 5) & 0x07);
		ovSubscription->validTo = ((buffer[13] & 0x1F) << 9) | ((buffer[14] & 0xFF) << 1) | ((buffer[15] >> 7) & 0x01);
	} else if (buffer[0] == 0x0a && buffer[1] == 0x02 && buffer[2] == 0xe0 && ((buffer[3] & 0xF0) == 0x00)) {
		ovSubscription->id = ((buffer[9] & 0xFF) << 4) | ((buffer[10] >> 4) & 0x0F);
		ovSubscription->company = ((buffer[4] >> 4) & 0x0F);
		ovSubscription->subscription = ((buffer[4] & 0x0F) << 12) | ((buffer[5] & 0xFF) << 4) | ((buffer[6] >> 4) & 0x0F);
		ovSubscription->validFrom = ((buffer[12] & 0x01) << 13) | ((buffer[13] & 0xFF) << 5) | ((buffer[14] >> 3) & 0x1F);
		if ((((buffer[11] & 0x1F) << 7) | ((buffer[12] >> 1) & 0x7F)) == 31) {
			ovSubscription->validTo = ((buffer[16] & 0xFF) << 6) | ((buffer[17] >> 2) & 0x3F);
		}
		if ((((buffer[11] & 0x1F) << 7) | ((buffer[12] >> 1) & 0x7F)) == 21) {
			ovSubscription->validTo = ((buffer[14] & 0x07) << 11) | ((buffer[15] & 0xFF) << 3) | ((buffer[16] >> 5) & 0x07);
		}
	} else {
		ovSubscription->valid = 1;
	}
}

//! Interpertate a Classic Transaction
void OvcClassicTransaction(unsigned char * buffer, int offset, int start, int length, ov_data *ovTrans) {
	bool bKnown = true;
	int iBitOffset = 53; //Ident, Date, Time
	
	memset(ovTrans, 0, sizeof(ov_data));
	ovTrans->transfer = -3;
	if (buffer[0] == 0x00 && buffer[1] == 0x00 && buffer[2] == 0x00 && (buffer[3] & 0xF0) == 0x00) {
		ovTrans->valid = 0;
		return;
	}
	ovTrans->valid = 1;
	ovTrans->location = offset;
	ovTrans->vehicleId = 0;
	ovTrans->date = ((buffer[3] & 0x0F) << 10) | ((buffer[4] & 0xFF) << 2) | ((buffer[5] >> 6) & 0x03);
	ovTrans->time = ((buffer[5] & 0x3F) << 5) | ((buffer[6] >> 3) & 0x1F);
	if (buffer[3] & 0x10) return;
	if (buffer[3] & 0x20) {
		ovTrans->unknownConstant = GetBitsFromBuffer(buffer, iBitOffset, 24);
		iBitOffset += 24;
	}
	if (buffer[3] & 0x40) {
		ovTrans->transfer = GetBitsFromBuffer(buffer, iBitOffset, 7);
		iBitOffset += 7;
	}
	if (buffer[3] & 0x80) return;
	if (buffer[2] & 0x01) {
		ovTrans->company = GetBitsFromBuffer(buffer, iBitOffset, 16);
		iBitOffset += 16;
	}
	if (buffer[2] & 0x02) return;
	if (buffer[2] & 0x04) {
		ovTrans->id = GetBitsFromBuffer(buffer, iBitOffset, 24);
		iBitOffset += 24;
	}
	if (buffer[2] & 0x08) return;
	if (buffer[2] & 0x10) {
		ovTrans->station = GetBitsFromBuffer(buffer, iBitOffset, 16);
		iBitOffset += 16;
	}
	if (buffer[2] & 0x20) return;
	if (buffer[2] & 0x40) {
		ovTrans->poleid = GetBitsFromBuffer(buffer, iBitOffset, 24);
		iBitOffset += 24;
	}
	if (buffer[2] & 0x80) return;
	if (buffer[1] & 0x01) return;
	if (buffer[1] & 0x02) return;
	if (buffer[1] & 0x04) {
		ovTrans->vehicleId = GetBitsFromBuffer(buffer, iBitOffset, 16);
		iBitOffset += 16;
	}
	if (buffer[1] & 0x08) return;
	if (buffer[1] & 0x10) {
		ovTrans->productId = GetBitsFromBuffer(buffer, iBitOffset, 5);
		iBitOffset += 5;
	}
	if (buffer[1] & 0x20) return;
	if (buffer[1] & 0x40) return;
	if (buffer[1] & 0x80) return;
	if (buffer[0] & 0x01) {
		ovTrans->unknownConstant2 = GetBitsFromBuffer(buffer, iBitOffset, 16);
		iBitOffset += 16;
	}
	if (buffer[0] & 0x02) return;
	if (buffer[0] & 0x04) return;
	if (buffer[0] & 0x08) {
		ovTrans->amount = GetBitsFromBuffer(buffer, iBitOffset, 16);
		iBitOffset += 16;
	}
}

void GetSubscription(unsigned int company, unsigned int subscription, char *out) {
	if (company == 4 && subscription == 5) {
		sprintf(out, "OV-jaarkaart");
	} else if (company == 4 && subscription == 7) {
		sprintf(out, "OV-Bijkaart 1e klas");
	} else if (company == 4 && subscription == 17) {
		sprintf(out, "NS Businesscard");
	} else if (company == 4 && subscription == 25) {
		sprintf(out, "Voordeelurenabonnement (twee jaar)");
	} else if (company == 4 && subscription == 175) {
		sprintf(out, "Studenten OV-chipkaart week (2009)");
	} else if (company == 4 && subscription == 176) {
		sprintf(out, "Studenten OV-chipkaart weekend (2009)");
	} else if (company == 4 && subscription == 177) {
		sprintf(out, "Studentenkaart korting week (2009)");
	} else if (company == 4 && subscription == 178) {
		sprintf(out, "Studentenkaart korting weekend (2009)");
	} else if (company == 4 && subscription == 201) {
		sprintf(out, "Reizen op saldo bij NS, 1e klasse");
	} else if (company == 4 && subscription == 202) {
		sprintf(out, "Reizen op saldo bij NS, 2de klasse");
	} else if (company == 4 && subscription == 206) {
		sprintf(out, "Voordeelurenabonnement reizen op saldo");
	} else if (company == 4 && subscription == 229) {
		sprintf(out, "Reizen op saldo (tijdelijk eerste klas)");
	} else if (company == 7 && subscription == 1574) {
		sprintf(out, "DALU Dalkorting");
	} else if (company == 1 && subscription == 1682) {
		sprintf(out, "Daluren Oost-Nederland");
	} else if (company == 12 && subscription == 2502) {
		sprintf(out, "Student weekend-vrij");
	} else if (company == 12 && subscription == 2503) {
		sprintf(out, "Student week-korting");
	} else if (company == 12 && subscription == 2505) {
		sprintf(out, "Student week-vrij");
	} else if (company == 12 && subscription == 2506) {
		sprintf(out, "Student weekend-korting");
	} else if (company == 2 && subscription == 3005) {
		sprintf(out, "Fietssupplement");
	} else {
		sprintf(out, "%u", subscription);
	}
}