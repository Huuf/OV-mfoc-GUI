#pragma once
#ifndef MFOCH_H
#define MFOCH_H

#include <SDKDDKVer.h>

#include <nfc/nfc.h>

#include <list>

#define u_int32_t uint32_t

#define MEM_CHUNK               10000
#define TRY_KEYS                150

// Number of trailers == number of sectors
// 16x64b = 16
#define NR_TRAILERS_1k  (16)
// 32x64b + 8*256b = 40
#define NR_TRAILERS_4k  (40)

#define MAX_FRAME_LEN 264

// Used for counting nonce distances, explore [nd-value, nd+value]
#define DEFAULT_TOLERANCE       20

// Default number of distance probes
#define DEFAULT_DIST_NR         15

// Default number of probes for a key recovery for one sector
#define DEFAULT_PROBES_NR       600

// Number of sets with 32b keys
#define DEFAULT_SETS_NR         2

#define odd_parity(i) (( (i) ^ (i)>>1 ^ (i)>>2 ^ (i)>>3 ^ (i)>>4 ^ (i)>>5 ^ (i)>>6 ^ (i)>>7 ^ 1) & 0x01)

typedef struct {
	byte_t KeyA[6];
	byte_t KeyB[6];
	bool foundKeyA;
	bool foundKeyB;
        byte_t trailer;                         // Value of a trailer block
} sector;
 
typedef struct {
        uint32_t       *distances;
        uint32_t       median;
        uint32_t       num_distances;
        uint32_t       tolerance;
        byte_t          parity[3];              // used for 3 bits of parity information
} denonce;                                      // Revealed information about nonce 
 
typedef struct {
        nfc_target_info_t  ti;
        sector *        sectors;                // Allocate later, we do not know the number of sectors yet
	sector		e_sector;		// Exploit sector
        uint32_t        num_sectors;
        uint32_t        num_blocks;
        uint32_t        uid;
        bool            b4K;    
} mftag;
 
typedef struct {
        uint64_t        *possibleKeys;
        uint32_t        size;
} pKeys;

typedef struct {
	uint64_t        *brokenKeys;
	uint32_t        size;
} bKeys;

typedef struct {
        nfc_device_t    *pdi;
} mfreader;

typedef struct {
        uint64_t        key;
        int             count;
} countKeys;

typedef struct{
	uint8_t sector;
	byte_t KeyA[6];
	byte_t KeyB[6];
	byte_t Data[16][16];
}mifare_sector;

typedef struct{
	char keyType;
	int sector;
	int probe;
	int set;
	unsigned __int64 duration;
}performance;

extern bool stopreadingcard;

//! Retreive the keys and read a card
/** @param sets the number of times that there should be information collected from the card
 * @param keyDir the folder where the keys are stored
 * @param buffer the output where the card data will be stored
 * @param bufferszie the size of the buffer
 * @param skipToSector when the reading starts, at which sector does the reading start
 * @param keyA Use A keys
 * @param keyB Use B keys
 * @param UpdateSectorStatus Sector status changed, char = key type, int = sector, byte_t = status 0 = no info, 1 = busy retreiving key, 2 = has key
 * @param UpdateStatusMessage a message for the user
 * @param SetCardInfo Set found card information
 * @return the number of bytes retreived from the card
 */
int ReadCard(nfc_device_desc_t *device, std::list<performance> *performanceData, int sets, char *keyDir, unsigned char *buffer, int buffersize, int skipToSector, bool keyA, bool keyB, void (*UpdateSectorStatus)(char, int, byte_t), void (*UpdateStatusMessage)(char *status), void (*SetCardInfo)(char *status));
int WriteCard(nfc_device_desc_t *device, char *keyDir, unsigned char *buffer, int buffersize, bool keyA, bool keyB, bool writeKeys, void (*UpdateSectorStatus)(char, int, byte_t), void (*UpdateStatusMessage)(char *status), void (*SetCardInfo)(char *status));
#endif