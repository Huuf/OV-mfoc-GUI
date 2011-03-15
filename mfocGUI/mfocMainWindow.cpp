/*  
 
Mifare Classic Offline Cracker version 0.08
 
Requirements: crapto1 library http://code.google.com/p/crapto1
libnfc                        http://www.libnfc.org
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 
Contact: <mifare@nethemba.com>

Porting to libnfc 1.3.3: Michal Boska <boska.michal@gmail.com>
Porting to libnfc 1.3.9: Romuald Conty <romuald@libnfc.org>
Porting to Windows by THC - University of Twente
Adding GUI + Reading Data - Anon 122 + Performance improvements <openov@huuf.net>
-Used Python version (https://github.com/wvengen/ovc-tools) for partial interpertation of data

URL http://eprint.iacr.org/2009/137.pdf
URL http://www.sos.cs.ru.nl/applications/rfid/2008-esorics.pdf
URL http://www.cosic.esat.kuleuven.be/rfidsec09/Papers/mifare_courtois_rfidsec09.pdf
URL http://www.cs.ru.nl/~petervr/papers/grvw_2009_pickpocket.pdf
*/

#pragma comment (lib, "nfc.lib")
#pragma comment (lib, "ComCtl32.lib")
#pragma comment (lib, "gdiplus.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include <stdio.h>
#include <Windows.h>
#include <Commctrl.h>
#include <direct.h>
#include <GdiPlus.h>
#include <stdlib.h>
#include <process.h>
#include <list>
#include <time.h>
#include <Shlobj.h>
using namespace Gdiplus;

#include "mfoc.h"
#include "mfocMainWindow.h"
#include "resource.h"
#include "OVData.h"
#include "OVStations.h"

char *startDir; //Working directory
char *DatabaseFile; //Database file
char dumpToFileDir[MAX_PATH] = "";
bool readingFile = false;
bool readingCard = false;
Image * ovImg;
unsigned char *lastDump = NULL;
int lastDumpSize = 0;
nfc_device_desc_t *pnddDevices;

HWND hMain; //Main window handle
HWND hCardID, hStatus, hValue;
HWND hMainTabControl;

HWND hOverlay;
HWND hReaderL, hReader;
HWND hReadData, hReadFile, hExport, hWritedata, hWritekeys;
HWND hDumpToFile, hSelectDirectoryDump, hDumpDirectory;
HWND hSubmitDump;
HWND hUseHotkey, hUseHotkeyKey, hUseHotkeyLooseFocus;
HWND hNonOVCard, hOVCard, hOVCardEverything;
HWND hShowLocations, hShowDuplicates;
HWND hNumberOfSetsL, hNumberOfSets;
HWND hUseKeyA, hSectors;
HWND hUseKeyB, hSectorsB;
HWND hSector;

HWND hStatistics;
HWND hData;
HWND hSubscriptions;

const HMENU hmMain =                (HMENU)100; //Main window handle
const HMENU hmCardID =              (HMENU)101;
const HMENU hmStatus =              (HMENU)102;
const HMENU hmValue =               (HMENU)103;
const HMENU hmMainTabControl =      (HMENU)104;

const HMENU hmOverlay =             (HMENU)105;
const HMENU hmReaderL =             (HMENU)106;
const HMENU hmReader =              (HMENU)107;
const HMENU hmReadData =            (HMENU)108;
const HMENU hmReadFile =            (HMENU)109;
const HMENU hmExport =              (HMENU)110;
const HMENU hmWritedata =           (HMENU)111;
const HMENU hmWritekeys =           (HMENU)112;
const HMENU hmDumpToFile =          (HMENU)113;
const HMENU hmSelectDirectoryDump = (HMENU)114;
const HMENU hmDumpDirectory =       (HMENU)115;
const HMENU hmSubmitDump =          (HMENU)116;
const HMENU hmNonOVCard =           (HMENU)117;
const HMENU hmOVCard =              (HMENU)118;
const HMENU hmOVCardEverything =    (HMENU)119;
const HMENU hmShowLocations =       (HMENU)120;
const HMENU hmShowDuplicates =      (HMENU)121;
const HMENU hmNumberOfSetsL =       (HMENU)122;
const HMENU hmNumberOfSets =        (HMENU)123;
const HMENU hmUseKeyA =             (HMENU)124;
const HMENU hmSectors =             (HMENU)125;
const HMENU hmUseKeyB =             (HMENU)126;
const HMENU hmSectorsB =            (HMENU)127;
const HMENU hmUseHotkey =           (HMENU)128;
const HMENU hmUseHotkeyKey =        (HMENU)129;
const HMENU hmUseHotkeyLooseFocus = (HMENU)130;

const HMENU hmStatistics =          (HMENU)131;
const HMENU hmData =                (HMENU)132;
const HMENU hmSubscriptions =       (HMENU)133;


int iHeiValue, iHeiCardID, iHeiStatus;
int iDumpDirectoryLeft, iDumpDirectoryHeight;
int iTabLeft, iTabTop;

BOOL InitListViewColumnsReis(HWND hWndListView);
BOOL InitListViewColumnsAbonnementen(HWND hWndListView);
void DisplayTab(int page);
void Handle_DumpToFileChange();
void Handle_TypeofcardChange();
void Handle_UseKeyAChange();
void Handle_UseKeyBChange();
void Handle_WM_COMMAND(HWND hwnd, WPARAM wParam);
void Handle_WM_HSCROLL();
LRESULT Handle_WM_NOTIFY(HWND hwnd, LPARAM lParam);
void Handle_WM_PAINT(HWND hwnd);
void Handle_WM_CREATE(HWND hwnd);
void LoadDefaultSettings();
void LoadLogo();
void LoadSettings();
void SaveSettings();
void SetCardID(char *message);
void SetSectorStatus(char type, int sector, byte_t status);
void Update_All_Controls();
void SetSectorStatus(char type, int sector, byte_t status);
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
RectF MeasureString(HDC hdc, bool big, const char *string);
void SetStatusmessage(char* message);
static void StartReading(void *parm);

std::list<ov_data> allData;
std::list<ov_Subscription> allSubs;
char szFileName[MAX_PATH] = "";
bool initialisedFont = false;
Graphics *graphics;
Font *fGDINormal;
Font *fGDIBig;
PointF pfIn(0.0f, 0.0f);

RectF MeasureString(HDC hdc, bool big, const char *string) {
	if (!initialisedFont) {
		initialisedFont = true;
		graphics = new Graphics(hdc);
		HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
		fGDINormal = new Font(hdc, hFont);
		hFont = CreateFont(-MulDiv(17, GetDeviceCaps(hdc, LOGPIXELSY), 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FF_DONTCARE, "Arial");
		fGDIBig = new Font(hdc, hFont);
	}
	RectF rOut;
	WCHAR *converted = (WCHAR *)malloc((strlen(string) + 1) * sizeof(WCHAR));
	memset(converted, 0, (strlen(string) + 1) * sizeof(WCHAR));
	int nLen = MultiByteToWideChar( CP_ACP, 0, string, -1, NULL, NULL ); 
	MultiByteToWideChar( CP_ACP, 0, string, -1, converted, nLen ); 
	graphics->MeasureString(converted, -1, big ? fGDIBig : fGDINormal, pfIn, &rOut);
	return rOut;
}

//! The user-provided entry point for a graphical Windows-based application.
/** @param hInstance A handle to the current instance of the application
 * @param hPrevInstance A handle to the previous instance of the application. This parameter is always NULL.
 * @param lpCmdLine The command line for the application, excluding the program name.
 * @param nCmdShow Controls how the window is to be shown
 * @return If the function succeeds, terminating when it receives a WM_QUIT message, it should return the exit value contained in that message's wParam parameter. If the function terminates before entering the message loop, it should return zero.
 */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	WNDCLASSEX wc;
	HWND hwnd;
	MSG Msg;

	GdiplusStartupInput gdiPlusInput;
	ULONG_PTR token;
	//load GDI+ for drawing the Logo
	GdiplusStartup(&token, &gdiPlusInput, NULL);
	
	//Load the logo
	LoadLogo();

	//Load XP Style controls
	InitCommonControls();

	ghInstance = hInstance;

	lastDump = (unsigned char *)malloc(4096);

	if (!(pnddDevices = (nfc_device_desc_t*)malloc (MAX_DEVICE_COUNT * sizeof (*pnddDevices)))) {
		MessageBox(NULL, "Could not reserve memory for NFC Devices!", "Error!", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	//Set the start-directory for key-files, database and dumpfile writing
	if (NULL == (startDir = _getcwd(NULL, 0))) {
		MessageBox(NULL, "Could not retreive the current directory!", "Error!", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}
	sprintf(dumpToFileDir, "%s", startDir);

	//Set up database
	DatabaseFile = (char*)malloc(strlen(startDir) + 15);
	sprintf(DatabaseFile, "%s/stations.db3", startDir);

	//Register the Window Class
	wc.cbSize        = sizeof(WNDCLASSEX);
	wc.style         = 0;
	wc.lpfnWndProc   = WndProc;
	wc.cbClsExtra    = 0;
	wc.cbWndExtra    = 0;
	wc.hInstance     = hInstance;
	wc.hIcon         = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_MAIN_ICON));
	wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)GetSysColorBrush(COLOR_BTNFACE);
	wc.lpszMenuName  = NULL;
	wc.lpszClassName = g_szClassName;
	wc.hIconSm       = (HICON)LoadImage(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_MAIN_ICON), IMAGE_ICON, 16, 16, 0);

	if(!RegisterClassEx(&wc)) {
		MessageBox(NULL, "Window Registration Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	//Create the Window
	hwnd = CreateWindowEx(NULL, g_szClassName, "MiFare Offline Cracker GUI + OV Data interperter: V29", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, hInstance, NULL);

	if(NULL == hwnd) {
		MessageBox(NULL, "Window Creation Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}
	
	hMain = hwnd;
	ShowWindow(hwnd, nCmdShow);
	UpdateWindow(hwnd);
	

	//Message Loop
	while(GetMessage(&Msg, NULL, 0, 0) != 0) {
		TranslateMessage(&Msg);
		DispatchMessage(&Msg);
	}

	GdiplusShutdown(token);

	return Msg.wParam;
}

//! Retreive the OV-Chipcard logo from the resources
void LoadLogo() {
	HRSRC hRsrc = FindResource(NULL,MAKEINTRESOURCE(102),RT_RCDATA);
	if (NULL == hRsrc) return;
	HGLOBAL hgRsrc = LoadResource(NULL, hRsrc);
	if (NULL == hgRsrc) return;
	int size = SizeofResource(NULL, hRsrc);
	HGLOBAL hgDest = GlobalAlloc(GMEM_FIXED, size);
	LPVOID resPtr = LockResource(hgRsrc);
	memcpy(hgDest,resPtr,size);
	FreeResource(hgRsrc);
	LPSTREAM pStream;
	CreateStreamOnHGlobal(hgDest,true,&pStream);
	ovImg = new Image(pStream, false);
	GlobalFree(hgDest);
}

//! Set the default settings to the controls
void LoadDefaultSettings() {
	//Dump To File
	SendMessage(hDumpToFile, BM_SETCHECK, BST_UNCHECKED, NULL);

	//Type of Dump
	CheckRadioButton(hMain, (int)hmNonOVCard, (int)hmOVCardEverything, (int)hmOVCard);

	//Show Location
	SendMessage(hShowLocations, BM_SETCHECK, BST_UNCHECKED, NULL);

	//Show Duplicates
	SendMessage(hShowDuplicates, BM_SETCHECK, BST_UNCHECKED, NULL);

	//Sets
	SendMessage(hNumberOfSets, TBM_SETPOS, TRUE, (LPARAM)DEFAULT_SETS_NR); //TODO

	//Use Key A
	SendMessage(hUseKeyA, BM_SETCHECK, BST_CHECKED, NULL);

	//Use Key B
	SendMessage(hUseKeyB, BM_SETCHECK, BST_UNCHECKED, NULL);
}

//! Load the settings from the settings file
void LoadSettings() {
	readingFile = true;
	FILE *fSettings;
	char *settingsFilename = (char *)malloc(strlen(startDir) + 16);
	sprintf(settingsFilename, "%s\\settings.dump", startDir);
	int c;
	int d;
	int version;
	int stLen;

	//Check if Settings File Exists
	if (NULL != (fSettings = fopen(settingsFilename, "rb"))) {
		//Version of settings file
		version = getc(fSettings);
		if (version == 1 || version == 2) {
			//Dump To File
			c = getc(fSettings);
			SendMessage(hDumpToFile, BM_SETCHECK, c == 1 ? BST_CHECKED : BST_UNCHECKED, NULL);


			//Type of Dump
			c = getc(fSettings);
			switch (c) {
			case 0: //OV Card - Read Everything
				CheckRadioButton(hMain, (int)hmNonOVCard, (int)hmOVCardEverything, (int)hmOVCardEverything);
				break;
			case 1: //OV Card
				CheckRadioButton(hMain, (int)hmNonOVCard, (int)hmOVCardEverything, (int)hmOVCard);
				break;
			case 2: //Non-OV Card
				CheckRadioButton(hMain, (int)hmNonOVCard, (int)hmOVCardEverything, (int)hmNonOVCard);
				break;
			}

			//Show Location
			c = getc(fSettings);
			SendMessage(hShowLocations, BM_SETCHECK, c == 1 ? BST_CHECKED : BST_UNCHECKED, NULL);

			//Hide Duplicates
			c = getc(fSettings);
			SendMessage(hShowDuplicates, BM_SETCHECK, c == 1 ? BST_CHECKED : BST_UNCHECKED, NULL);

			//Sets
			c = getc(fSettings);
			SendMessage(hNumberOfSets, TBM_SETPOS, TRUE, (LPARAM)c);

			//Use Key A
			c = getc(fSettings);
			SendMessage(hUseKeyA, BM_SETCHECK, c == 1 ? BST_CHECKED : BST_UNCHECKED, NULL);

			//Use Key B
			c = getc(fSettings);
			SendMessage(hUseKeyB, BM_SETCHECK, c == 1 ? BST_CHECKED : BST_UNCHECKED, NULL);

			if (version == 2) {
				//Use Key B
				c = getc(fSettings);
				SendMessage(hUseHotkey, BM_SETCHECK, c == 1 ? BST_CHECKED : BST_UNCHECKED, NULL);
				c = getc(fSettings);//modifier
				d = getc(fSettings);//key
				SendMessage(hUseHotkeyKey, HKM_SETHOTKEY, c << 8 | d, NULL);
			}

			//Dump To Directory
			fgets(dumpToFileDir, MAX_PATH, fSettings);
		}
		else {
			LoadDefaultSettings();
		}
		fclose(fSettings);
	}
	else {
		LoadDefaultSettings();
	}
	free(settingsFilename);
	readingFile = false;
	SendMessage(hDumpDirectory, WM_SETTEXT, 0, (LPARAM)dumpToFileDir);
}

//! Save the current settings to a file
void SaveSettings() {
	if (readingFile) return;
	FILE *fSettings;
	char *settingsFilename = (char *)malloc(strlen(startDir) + 16);
	sprintf(settingsFilename, "%s\\settings.dump", startDir);
	int c;
	int stLen;
	WORD iData = LOWORD(SendMessage(hUseHotkeyKey, HKM_GETHOTKEY, NULL, NULL));
	BYTE bVirtualKey = LOBYTE(iData);
	BYTE bKeyMod = HIBYTE(iData);


	//Check if Settings File Exists
	if (fSettings = fopen(settingsFilename, "wb")) {
		//Version of settings file
		putc(2, fSettings);
		
		//Dump To File
		putc(SendMessage(hDumpToFile, BM_GETCHECK, NULL, NULL) == BST_CHECKED ? 1 : 0, fSettings);

			
		//Type of Dump
		putc((SendMessage(hOVCardEverything, BM_GETCHECK, NULL, NULL) == BST_CHECKED) ? 0 : ((SendMessage(hOVCard, BM_GETCHECK, NULL, NULL) == BST_CHECKED) ? 1 : 2), fSettings);

		//Show Location
		putc(SendMessage(hShowLocations, BM_GETCHECK, NULL, NULL) == BST_CHECKED ? 1 : 0, fSettings);

		//Hide Duplicates
		putc(SendMessage(hShowDuplicates, BM_GETCHECK, NULL, NULL) == BST_CHECKED ? 1 : 0, fSettings);

		//Sets
		c = SendMessage(hNumberOfSets, TBM_GETPOS, NULL, NULL);
		putc(c, fSettings);

		//Use Key A
		putc(SendMessage(hUseKeyA, BM_GETCHECK, NULL, NULL) == BST_CHECKED ? 1 : 0, fSettings);

		//Use Key B
		putc(SendMessage(hUseKeyB, BM_GETCHECK, NULL, NULL) == BST_CHECKED ? 1 : 0, fSettings);

		//Use Hotkeys
		putc(SendMessage(hUseHotkey, BM_GETCHECK, NULL, NULL) == BST_CHECKED ? 1 : 0, fSettings);

		//Hotkeys modifier
		putc(bKeyMod, fSettings);

		//Hotkeys virtual key
		putc(bVirtualKey, fSettings);

		//Dump To Directory
		fputs((char *)&dumpToFileDir, fSettings);

		fflush(fSettings);
		fclose(fSettings);
	}
	free(settingsFilename);
}

//! Initialize the listview columns
/** @param hWndListView the handle to the listview
 * @return true if succeeded in adding the columns
 */
BOOL InitListViewColumnsReis(HWND hWndListView) {
	LVCOLUMN lvc; 
	int i = 0;
	int iShowLocation = SendMessage(hShowLocations, BM_GETCHECK, NULL, NULL) == BST_CHECKED ? 1 : 0;

	while (ListView_DeleteColumn(hWndListView, 0));

	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM; 
	lvc.iSubItem = i;
	lvc.pszText = "ID";
	lvc.cx = 50;
	lvc.fmt = LVCFMT_LEFT;

	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;

	if (iShowLocation) {
		lvc.iSubItem = i;
		lvc.pszText = "Location";
		if (ListView_InsertColumn(hWndListView, i, &lvc) == -1) return FALSE;
		i++;
	}

	lvc.iSubItem = i;
	lvc.pszText = "Date";
	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;
	lvc.iSubItem = i;
	lvc.pszText = "Time";
	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;
	lvc.iSubItem = i;
	lvc.pszText = "Company";
	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;
	lvc.iSubItem = i;
	lvc.pszText = "Transfer";
	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;
	lvc.iSubItem = i;
	lvc.pszText = "Vehicle";
	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;
	lvc.iSubItem = i;
	lvc.pszText = "Machine";
	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;
	lvc.iSubItem = i;
	lvc.pszText = "Amount";
	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;
	lvc.iSubItem = i;
	lvc.pszText = "Station";
	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;

	for (i = 0; i < 10; i++)
		ListView_SetColumnWidth(hWndListView, i, -2);
	
	return TRUE;
}

//! Initialize the listview columns
/** @param hWndListView the handle to the listview
 * @return true if succeeded in adding the columns
 */
BOOL InitListViewColumnsAbonnementen(HWND hWndListView) {
	LVCOLUMN lvc; 
	int i = 0;
	int iShowLocation = SendMessage(hShowLocations, BM_GETCHECK, NULL, NULL) == BST_CHECKED ? 1 : 0;

	while (ListView_DeleteColumn(hWndListView, 0));

	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM; 
	lvc.iSubItem = i;
	lvc.pszText = "ID";
	lvc.cx = 50;
	lvc.fmt = LVCFMT_LEFT;

	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;

	if (iShowLocation) {
		lvc.iSubItem = i;
		lvc.pszText = "Location";
		if (ListView_InsertColumn(hWndListView, i, &lvc) == -1) return FALSE;
		i++;
	}

	lvc.iSubItem = i;
	lvc.pszText = "Company";
	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;
	lvc.iSubItem = i;
	lvc.pszText = "Valid From";
	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;
	lvc.iSubItem = i;
	lvc.pszText = "Valid To";
	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;
	lvc.iSubItem = i;
	lvc.pszText = "Subscription";
	if (-1 == ListView_InsertColumn(hWndListView, i, &lvc)) return FALSE; 
	i++;

	for (i = 0; i < 7; i++)
		ListView_SetColumnWidth(hWndListView, i, -2);
	
	return TRUE;
}

RECT GetRequiredRectForCheckbox(HDC hdc, const char *text) {
	RectF rfS = MeasureString(hdc, false, text);
	RECT lpRect;
	lpRect.left = 0;
	lpRect.top = 0;
	lpRect.right = ceil(rfS.Width);
	lpRect.bottom = ceil(rfS.Height);
	AdjustWindowRectEx(&lpRect, BS_AUTOCHECKBOX | WS_CHILD | WS_VISIBLE, false, 0);
	lpRect.right += 25;
	lpRect.bottom += 5;
  return lpRect;
}

void LoadCurrentCard() {
	int iSelectedDevice = SendMessage(hReader, CB_GETCURSEL, NULL, NULL);
	nfc_device_t *pnd;
	size_t  szTargetFound;
	char StatusBuffer[600];

	if (CB_ERR == iSelectedDevice) {
		SetCardID("Card: No Reader Selected");
	}	else {
		nfc_target_info_t anti[1];
		pnd = nfc_connect (&(pnddDevices[iSelectedDevice]));
		
		nfc_initiator_init(pnd);

		// Drop the field for a while
		if (!nfc_configure (pnd, NDO_ACTIVATE_FIELD, false)) { nfc_disconnect(pnd); return; }
    // Let the reader only try once to find a tag
		if (!nfc_configure (pnd, NDO_INFINITE_SELECT, false)) { nfc_disconnect(pnd); return; }
    // Configure the CRC and Parity settings

		if (!nfc_configure (pnd, NDO_HANDLE_CRC, true)) { nfc_disconnect(pnd); return; }
		if (!nfc_configure (pnd, NDO_HANDLE_PARITY, true)) { nfc_disconnect(pnd); return; }
    // Enable field so more power consuming cards can power themselves up
		if (!nfc_configure (pnd, NDO_ACTIVATE_FIELD, true)) { nfc_disconnect(pnd); return; }

		if (!nfc_configure (pnd, NDO_AUTO_ISO14443_4, true)) { nfc_disconnect(pnd); return; }
		
		if (nfc_initiator_list_passive_targets (pnd, NM_ISO14443A_106, anti, 1, &szTargetFound)) {
      size_t  n;
      for (n = 0; n < szTargetFound; n++) {
				switch (anti[n].nai.btSak) {
				case 0x04: sprintf(StatusBuffer, "Card: Any MIFARE CL1, uid: "); break;
				case 0x24: sprintf(StatusBuffer, "Card: MIFARE DESFire (EV1) CL1, uid: "); break;
				case 0x00: sprintf(StatusBuffer, "Card: MIFARE Ultralight (C) CL2, uid: "); break;
				case 0x09: sprintf(StatusBuffer, "Card: MIFARE Mini, uid: "); break;
				case 0x08: sprintf(StatusBuffer, "Card: MIFARE Classic 1K, uid: "); break;
				case 0x18: sprintf(StatusBuffer, "Card: MIFARE Classic 4K, uid: "); break;
				case 0x10: sprintf(StatusBuffer, "Card: MIFARE PLUS (CL2) 2K, uid: "); break;
				case 0x11: sprintf(StatusBuffer, "Card: MIFARE PLUS (CL2) 4K, uid: "); break;
				case 0x20: sprintf(StatusBuffer, "Card: MIFARE DESFire, uid: "); break;
				default:sprintf(StatusBuffer, "Card: Unknown, uid: "); break;
				}
				size_t i;
				for (i = 0; i < anti[n].nai.szUidLen; i++) {
					sprintf(StatusBuffer,"%s%02x", StatusBuffer, anti[n].nai.abtUid[i]);
				}
				
        SetCardID(StatusBuffer);
      }
    }
		// Reset the "advanced" configuration to normal
		nfc_configure(pnd, NDO_HANDLE_CRC, true);
		nfc_configure(pnd, NDO_HANDLE_PARITY, true);
		nfc_configure(pnd, NDO_INFINITE_SELECT, false);

		nfc_disconnect(pnd);
	}
}

void LoadReaders() {
	int iCurSel = SendMessage(hReader, CB_GETCURSEL, 0, 0);
	SendMessage(hReader, CB_RESETCONTENT, 0, 0);
	size_t szDeviceFound;
	int i;
	char buffer[500];
	nfc_list_devices (pnddDevices, MAX_DEVICE_COUNT, &szDeviceFound);
	for (i = 0; i < szDeviceFound; i++) {
		sprintf(buffer, "%s", pnddDevices[i].acDevice);
		SendMessage(hReader, CB_ADDSTRING, 0, (LPARAM)buffer);
	}
	if (szDeviceFound > 0) {
		if (iCurSel >= 0 && iCurSel < szDeviceFound) {
			SendMessage(hReader, CB_SETCURSEL, (WPARAM)iCurSel, 0);
		} else {
			SendMessage(hReader, CB_SETCURSEL, 0, 0);
		}
		//LoadCurrentCard();
	}
}

void Handle_WM_HOTKEY(WPARAM wParam) {
		if (wParam == 100) {
			ListView_DeleteAllItems(hData);
			ListView_DeleteAllItems(hSubscriptions);
			_beginthread(StartReading, 0, hMain );
		}
}

//! Handle the WM_CREATE, Creation of the window
/** @param hwnd The HWND from the WndProc function
 */
void Handle_WM_CREATE(HWND hwnd) {
	HFONT hFont;
	HFONT hFontBig;
	RECT checkboxRect;
	RECT clientRect;
	RectF rTMP;
	RectF rTMPMax;
	GetClientRect(hwnd, &clientRect);

	int i, iTopLabelHeight, iTMPTop, iTMPLeft;
	char BUFFER[100];
	hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
	hFontBig = CreateFont(-MulDiv(17, GetDeviceCaps(GetDC(hwnd), LOGPIXELSY), 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FF_DONTCARE, "Arial");
	HDC hdc = GetDC(hwnd);

	RectF rCardID = MeasureString(hdc, false, "Card: No card read yet.");
	RectF rStatus = MeasureString(hdc, false, "Card: Status: Waiting for user input.");
	RectF rValue = MeasureString(hdc, true, "Credit: €0,00");
	iHeiValue = ceil(rValue.Height);
	iHeiCardID = ceil(rCardID.Height);
	iHeiStatus = ceil(rStatus.Height);

	hCardID = CreateWindowEx(NULL, WC_STATIC, "Card: No card read yet.", WS_CHILD | WS_VISIBLE, 12, 9, clientRect.right - 64 - 12 - 6, ceil(rCardID.Height), hwnd, hmCardID, ghInstance, NULL);
	hStatus = CreateWindowEx(NULL, WC_STATIC, "Status: Waiting for user input.", WS_CHILD | WS_VISIBLE, 12, 9 + ceil(rCardID.Height) + 6, clientRect.right - 64 - 12 - 6, ceil(rStatus.Height), hwnd, hmStatus, ghInstance, NULL);
	hValue = CreateWindowEx(NULL, WC_STATIC, "Credit: €0,00", WS_CHILD | WS_VISIBLE, 12, 9 + ceil(rCardID.Height) + 6 + ceil(rStatus.Height) + 6, clientRect.right - 64 - 12 - 6, ceil(rValue.Height), hwnd, hmValue, ghInstance, NULL);
	iTopLabelHeight = 9 + ceil(rCardID.Height) + 6 + ceil(rStatus.Height) + 6 + ceil(rCardID.Height);
	iTopLabelHeight = (iTopLabelHeight > 64) ? iTopLabelHeight : 64;

	iTabLeft = 12;
	iTabTop = 12 + iTopLabelHeight + 6;
	hMainTabControl = CreateWindowEx(NULL, WC_TABCONTROL, "", WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE, iTabLeft, iTabTop, clientRect.right - 24, clientRect.bottom - 12 - iTopLabelHeight - 6 - 12, hwnd, hmMainTabControl, ghInstance, NULL);

	TCITEM tie;
	tie.mask = TCIF_TEXT;
	tie.pszText = "General";
	TabCtrl_InsertItem(hMainTabControl, 0, &tie);
	tie.pszText = "Statistics";
	TabCtrl_InsertItem(hMainTabControl, 1, &tie);
	tie.pszText = "Travel History";
	TabCtrl_InsertItem(hMainTabControl, 2, &tie);
	tie.pszText = "Subscriptions";
	TabCtrl_InsertItem(hMainTabControl, 3, &tie);

	RECT crTab;
	GetClientRect(hMainTabControl, &crTab);
	SendMessage(hMainTabControl, TCM_ADJUSTRECT, NULL, (LPARAM)&crTab);
	crTab.left += iTabLeft;
	crTab.right += iTabLeft;
	crTab.top += iTabTop;
	crTab.bottom += iTabTop;

	//Tab 1
	hOverlay = CreateWindowEx(NULL, WC_STATIC, "", WS_CHILD | WS_VISIBLE, crTab.left, crTab.top, crTab.right - crTab.left, crTab.bottom - crTab.top, hwnd, hmOverlay, ghInstance, NULL);
	
	//Line 0
	iTMPTop = crTab.top + 6;
	rTMP = MeasureString(hdc,false, "Reader:");
	hReader = CreateWindowEx(NULL, WC_COMBOBOX, "", WS_BORDER | WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, crTab.left + 6 + ceil(rTMP.Width), iTMPTop, 203, 0, hwnd, hmReader, ghInstance, NULL);
	
	int iItemHeight = SendMessage(hReader, CB_GETITEMHEIGHT, 0, 0);
	iItemHeight += (GetSystemMetrics(8) * 2);
	SetWindowPos(hReader, NULL, 0, 0, 203, iItemHeight, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER | SWP_NOZORDER);

	hReaderL = CreateWindowEx(NULL, WC_STATIC, "Reader:", WS_CHILD, crTab.left + 6, iTMPTop + (iItemHeight / 2) - (rTMP.Height / 2), ceil(rTMP.Width), rTMP.Height, hwnd, hmReaderL, ghInstance, NULL);
	iTMPTop += iItemHeight + 9;

	//Line 1
	rTMPMax = MeasureString(hdc,false, "Read data (Reader)");
	rTMP = MeasureString(hdc,false, "Read data (File)");
	if (rTMP.Width > rTMPMax.Width) rTMPMax.Width = rTMP.Width;
	if (rTMP.Height > rTMPMax.Height) rTMPMax.Height = rTMP.Height;
	rTMP = MeasureString(hdc,false, "Export (OV)");
	if (rTMP.Width > rTMPMax.Width) rTMPMax.Width = rTMP.Width;
	if (rTMP.Height > rTMPMax.Height) rTMPMax.Height = rTMP.Height;
	rTMP = MeasureString(hdc,false, "Write data (Reader)");
	if (rTMP.Width > rTMPMax.Width) rTMPMax.Width = rTMP.Width;
	if (rTMP.Height > rTMPMax.Height) rTMPMax.Height = rTMP.Height;
	int iButtonHeight = ceil(rTMPMax.Height) + 9;
	int iButtonWidth = ceil(rTMPMax.Width) + 12;

	hReadData = CreateWindowEx(NULL, WC_BUTTON, "&Read data (Reader)", WS_CHILD | BS_PUSHBUTTON, crTab.left + 6, iTMPTop, iButtonWidth, iButtonHeight, hwnd, hmReadData, ghInstance, NULL);
	hReadFile = CreateWindowEx(NULL, WC_BUTTON, "Read data (&File)", WS_CHILD | BS_PUSHBUTTON, crTab.left + 6 + iButtonWidth + 6, iTMPTop, iButtonWidth, iButtonHeight, hwnd, hmReadFile, ghInstance, NULL);
	hExport = CreateWindowEx(NULL, WC_BUTTON, "&Export (OV)", WS_CHILD | BS_PUSHBUTTON, crTab.left + 6 + iButtonWidth + 6 + iButtonWidth + 6, iTMPTop, iButtonWidth, iButtonHeight, hwnd, hmExport, ghInstance, NULL);
	hWritedata = CreateWindowEx(NULL, WC_BUTTON, "&Write data (Reader)", WS_CHILD | BS_PUSHBUTTON, crTab.left + 6 + iButtonWidth + 6 + iButtonWidth + 6 + iButtonWidth + 6, iTMPTop, iButtonWidth, iButtonHeight, hwnd, hmWritedata, ghInstance, NULL);
	checkboxRect = GetRequiredRectForCheckbox(hdc, "Write keys");
	hWritekeys = CreateWindowEx(NULL, WC_BUTTON, "Write keys", BS_AUTOCHECKBOX | WS_CHILD, crTab.left + 6 + iButtonWidth + 6 + iButtonWidth + 6 + iButtonWidth + 6 + iButtonWidth + 6, iTMPTop, checkboxRect.right + checkboxRect.left, iButtonHeight, hwnd, hmWritekeys, ghInstance, NULL);
	iTMPTop += iButtonHeight + 9;
	//Line 2
	checkboxRect = GetRequiredRectForCheckbox(hdc, "Dump to file");
	hDumpToFile = CreateWindowEx(NULL, WC_BUTTON, "Dump to file", BS_AUTOCHECKBOX | WS_CHILD, crTab.left + 6, iTMPTop, checkboxRect.right, iButtonHeight, hwnd, hmDumpToFile, ghInstance, NULL);
	rTMP = MeasureString(hdc,false, "Select Directory");
	hSelectDirectoryDump = CreateWindowEx(NULL, WC_BUTTON, "Select Directory", WS_CHILD | BS_PUSHBUTTON, crTab.left + 6 + checkboxRect.right + 6, iTMPTop, rTMP.Width + 12, iButtonHeight, hwnd, hmSelectDirectoryDump, ghInstance, NULL);
	RectF rTMP2 = MeasureString(hdc,false, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
	hDumpDirectory = CreateWindowEx(NULL, WC_STATIC, "CURRENT DIRECTORY", WS_CHILD, crTab.left + 6 + checkboxRect.right + 6 + rTMP.Width + 12 + 6, iTMPTop + (iButtonHeight / 2) - (rTMP2.Height / 2), 542, ceil(rTMP2.Height), hwnd, hmDumpDirectory, ghInstance, NULL);
	iDumpDirectoryHeight = iTMPTop + (iButtonHeight / 2) - (rTMP2.Height / 2);
	iDumpDirectoryLeft = crTab.left + 6 + checkboxRect.right + 6 + rTMP.Width + 12 + 6;
	iTMPTop += iButtonHeight + 9;
	//Line 3
	rTMP = MeasureString(hdc,false, "You can send in your dumps anonymously for research to ovdumps@huuf.info");
	hSubmitDump = CreateWindowEx(NULL, WC_STATIC, "You can send in your dumps anonymously for research to ovdumps@huuf.info", WS_CHILD | SS_NOTIFY, crTab.left + 6, iTMPTop + (iButtonHeight / 2) - (rTMP.Height / 2), ceil(rTMP.Width), iButtonHeight, hwnd, hmSubmitDump, ghInstance, NULL);
	iTMPTop += iButtonHeight + 9;

	//Line 4
	rTMP = MeasureString(hdc,false, "Loose Focus");
	iButtonHeight = ceil(rTMPMax.Height) + 9;
	iButtonWidth = ceil(rTMPMax.Width) + 12;

	checkboxRect = GetRequiredRectForCheckbox(hdc, "Use hotkey");
	hUseHotkey = CreateWindowEx(NULL, WC_BUTTON, "Use hotkey", BS_AUTOCHECKBOX | WS_CHILD, crTab.left + 6, iTMPTop + (iButtonHeight / 2) - (checkboxRect.bottom / 2), checkboxRect.right, checkboxRect.bottom, hwnd, hmUseHotkey, ghInstance, NULL);
	iTMPLeft = crTab.left + 6 + checkboxRect.right + 6;
	hUseHotkeyKey = CreateWindowEx(NULL, HOTKEY_CLASS, "", WS_VISIBLE | WS_CHILD | WS_DISABLED, iTMPLeft, iTMPTop + (iButtonHeight / 2) - 10, 203, 20, hwnd, hmUseHotkeyKey, ghInstance, NULL);
	iTMPLeft += 203 + 6;
	hUseHotkeyLooseFocus = CreateWindowEx(NULL, WC_BUTTON, "&Loose Focus", WS_CHILD | BS_PUSHBUTTON, iTMPLeft, iTMPTop, iButtonWidth, iButtonHeight, hwnd, hmUseHotkeyLooseFocus, ghInstance, NULL);
	iTMPTop += iButtonHeight + 9;

	//Line 5
	checkboxRect = GetRequiredRectForCheckbox(hdc, "Non-OV Card");
	hNonOVCard = CreateWindowEx(NULL, WC_BUTTON, "Non-OV Card", WS_CHILD | BS_AUTORADIOBUTTON, crTab.left + 6, iTMPTop, checkboxRect.right, checkboxRect.bottom, hwnd, hmNonOVCard, ghInstance, NULL);
	iTMPLeft = crTab.left + 6 + checkboxRect.right + 6;

	checkboxRect = GetRequiredRectForCheckbox(hdc, "OV Card");
	hOVCard = CreateWindowEx(NULL, WC_BUTTON, "OV Card", WS_CHILD | BS_AUTORADIOBUTTON, iTMPLeft, iTMPTop, checkboxRect.right, checkboxRect.bottom, hwnd, hmOVCard, ghInstance, NULL);
	iTMPLeft += checkboxRect.right + 6;

	checkboxRect = GetRequiredRectForCheckbox(hdc, "OV Card - Read Everything");
	hOVCardEverything = CreateWindowEx(NULL, WC_BUTTON, "OV Card - Read Everything", WS_CHILD | BS_AUTORADIOBUTTON, iTMPLeft, iTMPTop, checkboxRect.right, checkboxRect.bottom, hwnd, hmOVCardEverything, ghInstance, NULL);
	iTMPTop += checkboxRect.bottom + 9;

	//Line 6
	checkboxRect = GetRequiredRectForCheckbox(hdc, "Show location");
	hShowLocations = CreateWindowEx(NULL, WC_BUTTON, "Show location", BS_AUTOCHECKBOX | WS_CHILD, crTab.left + 6, iTMPTop, checkboxRect.right, checkboxRect.bottom, hwnd, hmShowLocations, ghInstance, NULL);
	iTMPLeft = crTab.left + 6 + checkboxRect.right + 6;
	checkboxRect = GetRequiredRectForCheckbox(hdc, "Show duplicates");
	hShowDuplicates = CreateWindowEx(NULL, WC_BUTTON, "Show duplicates", BS_AUTOCHECKBOX | WS_CHILD, iTMPLeft, iTMPTop, checkboxRect.right, checkboxRect.bottom, hwnd, hmShowDuplicates, ghInstance, NULL);
	iTMPTop += checkboxRect.bottom + 9;
	//Line 7
	rTMP = MeasureString(hdc, false, "Sets: 999");
	hNumberOfSetsL = CreateWindowEx(NULL, WC_STATIC, "Sets: 4", WS_CHILD, crTab.left + 6, iTMPTop, ceil(rTMP.Width), ceil(rTMP.Height), hwnd, hmNumberOfSetsL, ghInstance, NULL);
	iTMPTop += ceil(rTMP.Height) + 3;
	hNumberOfSets = CreateWindowEx(NULL, TRACKBAR_CLASS, "", TBS_AUTOTICKS | WS_CHILD, crTab.left + 6 + 13, iTMPTop, 203, 34, hwnd, hmNumberOfSets, ghInstance, NULL);
	iTMPTop += 34 + 9;
	//Line 8
	checkboxRect = GetRequiredRectForCheckbox(hdc, "Use Key A");
	hUseKeyA = CreateWindowEx(NULL, WC_BUTTON, "Use Key A", BS_AUTOCHECKBOX | WS_CHILD, crTab.left + 6, iTMPTop, checkboxRect.right, checkboxRect.bottom, hwnd, hmUseKeyA, ghInstance, NULL);
	iTMPTop += checkboxRect.bottom + 9;
	rTMP = MeasureString(hdc, false, "Sectors A:");
	hSectors = CreateWindowEx(NULL, WC_STATIC, "Sectors A:", WS_CHILD, crTab.left + 6, iTMPTop, ceil(rTMP.Width), ceil(rTMP.Height), hwnd, hmSectors, ghInstance, NULL);
	iTMPLeft = crTab.left + 6 + ceil(rTMP.Width);
	for (i = 0; i < 40; i++) {
		hSector = CreateWindowEx(NULL, WC_BUTTON, "", BS_AUTO3STATE | WS_CHILD | WS_DISABLED, iTMPLeft + (21 * (i % 20)), iTMPTop + ((i / 20) * 20), 15, 14, hwnd, (HMENU)(200 + i), ghInstance, NULL);
		SendMessage(hSector, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	}
	iTMPTop += 46;
	//Line 9
	checkboxRect = GetRequiredRectForCheckbox(hdc, "Use Key B");
	hUseKeyB = CreateWindowEx(NULL, WC_BUTTON, "Use Key B", BS_AUTOCHECKBOX | WS_CHILD, crTab.left + 6, iTMPTop, checkboxRect.right, checkboxRect.bottom, hwnd, hmUseKeyB, ghInstance, NULL);
	iTMPTop += checkboxRect.bottom + 9;
	rTMP = MeasureString(hdc, false, "Sectors B:");
	hSectorsB = CreateWindowEx(NULL, WC_STATIC, "Sectors B:", WS_CHILD, crTab.left + 6, iTMPTop, ceil(rTMP.Width), ceil(rTMP.Height), hwnd, hmSectorsB, ghInstance, NULL);
	iTMPLeft = crTab.left + 6 + ceil(rTMP.Width);
	for (i = 0; i < 40; i++) {
		hSector = CreateWindowEx(NULL, WC_BUTTON, "", BS_AUTO3STATE | WS_CHILD | WS_DISABLED, iTMPLeft + (21 * (i % 20)), iTMPTop + ((i / 20) * 20), 15, 14, hwnd, (HMENU)(300 + i), ghInstance, NULL);
		SendMessage(hSector, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	}
	
	//Tab 2
	hStatistics = CreateWindowEx(WS_EX_CLIENTEDGE, WC_EDIT, "You first have to read a card to see statistics.", WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL, crTab.left, crTab.top, crTab.right - crTab.left, crTab.bottom - crTab.top, hwnd, hmStatistics, ghInstance, NULL);
	//Tab 3
	hData = CreateWindowEx(LVS_EX_FULLROWSELECT, WC_LISTVIEW, "", WS_BORDER | WS_CHILD | LVS_REPORT, crTab.left, crTab.top, crTab.right - crTab.left, crTab.bottom - crTab.top, hwnd, hmData, ghInstance, NULL);
	//Tab 4
	hSubscriptions = CreateWindowEx(LVS_EX_FULLROWSELECT, WC_LISTVIEW, "", WS_BORDER | WS_CHILD | LVS_REPORT, crTab.left, crTab.top, crTab.right - crTab.left, crTab.bottom - crTab.top, hwnd, hmSubscriptions, ghInstance, NULL);
	//End tab control


	ListView_SetExtendedListViewStyle(hData, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	ListView_SetExtendedListViewStyle(hSubscriptions, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	InitListViewColumnsReis(hData);
	InitListViewColumnsAbonnementen(hSubscriptions);

	SendMessage(hReader, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hReaderL, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hMainTabControl, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hShowLocations, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hShowDuplicates, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hExport, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hDumpDirectory, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hOVCardEverything, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hOVCard, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hNonOVCard, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hSelectDirectoryDump, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hUseKeyB, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hUseKeyA, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hSectorsB, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hNumberOfSetsL, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hNumberOfSets, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hSectors, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hDumpToFile, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hReadFile, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hReadData, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hSubmitDump, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hStatistics, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hData, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hSubscriptions, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hStatus, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hCardID, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hWritedata, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hWritekeys, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hUseHotkey, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hUseHotkeyKey, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	SendMessage(hUseHotkeyLooseFocus, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
	

	//Bigger font
	
	SendMessage(hValue, WM_SETFONT, (WPARAM)hFontBig, MAKELPARAM(TRUE, 0));

	
	//Trackbar settings
	SendMessage(hNumberOfSets, TBM_SETRANGE, (WPARAM) TRUE, (LPARAM) MAKELONG(1, 8));
	SendMessage(hNumberOfSets, TBM_SETPAGESIZE, 0, (LPARAM) 1);
	SendMessage(hNumberOfSets, TBM_SETPOS, TRUE, (LPARAM)2);
	sprintf(BUFFER, "Sets: %i", 2);
	SendMessage(hNumberOfSetsL, WM_SETTEXT, 0, (LPARAM)&BUFFER);

	//Get all readers
	LoadReaders();
}

//! Handle the WM_CREATE, Creation of the window
/** @param page The tabpage to display, 0 based index
 */
void DisplayTab(int page) {
	int i;

	for (i = 105; i <= 130; i++) {
		ShowWindow(GetDlgItem(hMain, i), page == 0);
	}
	for (i = 200; i <= 239; i++) {
		ShowWindow(GetDlgItem(hMain, i), page == 0);
	}
	for (i = 300; i <= 339; i++) {
		ShowWindow(GetDlgItem(hMain, i), page == 0);
	}
	ShowWindow(hStatistics, page == 1);
	ShowWindow(hData, page == 2);
	ShowWindow(hSubscriptions, page == 3);

}

LRESULT Handle_WM_NOTIFY(HWND hwnd, LPARAM lParam) {
	int iPage;
	HWND hTabC;
	switch (((LPNMHDR)lParam)->code) {
	case TCN_SELCHANGING:
		return FALSE;
	case TCN_SELCHANGE:
		DisplayTab(TabCtrl_GetCurSel(hMainTabControl));
		break;
	}
	return 0;
}

//! Handle the switching between the different type of cards
void Handle_TypeofcardChange() {
	int iSel = (SendMessage(hOVCardEverything, BM_GETCHECK, NULL, NULL) == BST_CHECKED) ? 0 : ((SendMessage(hOVCard, BM_GETCHECK, NULL, NULL) == BST_CHECKED) ? 1 : 2);
	EnableWindow(hShowLocations, iSel != 2);
	EnableWindow(hShowDuplicates, iSel != 2);
	EnableWindow(hExport, iSel != 2);
	EnableWindow(hWritedata, iSel == 2);
	EnableWindow(hWritekeys, iSel == 2);
}

void Handle_UsehotkeyKeyChange() {
	WORD iData = LOWORD(SendMessage(hUseHotkeyKey, HKM_GETHOTKEY, NULL, NULL));
	BYTE bVirtualKey = LOBYTE(iData);
	BYTE bKeyMod = HIBYTE(iData);
	char BUFFER[100];
	UnregisterHotKey(hMain, 100);
	if (SendMessage(hUseHotkey, BM_GETCHECK, NULL, NULL) == BST_CHECKED) {
		if (!RegisterHotKey(hMain, 100, bKeyMod, bVirtualKey)) {
			SetStatusmessage("Status: Failed to set the hotkey");
		}
	}
}

void Handle_UsehotkeyChange() {
	int iEna = SendMessage(hUseHotkey, BM_GETCHECK, NULL, NULL) == BST_CHECKED;
	EnableWindow(hUseHotkeyKey, iEna);
	Handle_UsehotkeyKeyChange();
}

//! Handle the checking and unchecking of the Dump To File checkbox
void Handle_DumpToFileChange() {
	int iEna = SendMessage(hDumpToFile, BM_GETCHECK, NULL, NULL) == BST_CHECKED;
	EnableWindow(hSelectDirectoryDump, iEna);
	EnableWindow(hDumpDirectory, iEna);
	InvalidateRect(hMain,NULL,true);
}

//! Handle the checking and unchecking of the Use A Keys checkbox
void Handle_UseKeyAChange() {
	EnableWindow(hSectors, SendMessage(hUseKeyA, BM_GETCHECK, NULL, NULL) == BST_CHECKED);
}

//! Handle the checking and unchecking of the Use B Keys checkbox
void Handle_UseKeyBChange() {
	EnableWindow(hSectorsB, SendMessage(hUseKeyB, BM_GETCHECK, NULL, NULL) == BST_CHECKED);
}

//! Update all controls so that they reflect the settings
void Update_All_Controls() {
	Handle_TypeofcardChange();
	Handle_DumpToFileChange();
	Handle_UsehotkeyChange();
	Handle_UsehotkeyKeyChange();
	Handle_UseKeyAChange();
	Handle_UseKeyBChange();
	Handle_WM_HSCROLL();
	InitListViewColumnsAbonnementen(hSubscriptions);
	InitListViewColumnsReis(hData);
}

//! Set the current Card ID
/** @param message the message to set to the UID label
 */
void SetCardID(char* message) {
	SendMessage(hCardID, WM_SETTEXT, 0, (LPARAM)message);
}

//! Set the status message
/** @param message The message to set to the status label
 */
void SetStatusmessage(char* message) {
	SendMessage(hStatus, WM_SETTEXT, 0, (LPARAM)message);
}

//! Convert a sector to the first block of a sector * size of block
/** @param sector The sector to convert
 * @return the block
 */
int mfclassic_getsector(int sector) {
	return (sector < 32) ? (sector * 0x40) : (0x800 + ((sector - 32) * 0x100));
}

//! Sorting function for the items
/** @param first first item to compare
 * @param second second item to compare
 * @return true if item 1 > item 2
 */
bool compare_ovdata(ov_data first, ov_data second) {
	if (first.date == second.date)
		return first.time > second.time;

	return first.date > second.date;
}

//! Sorting function for the items
/** @param first first item to compare
 * @param second second item to compare
 * @return true if item 1 > item 2
 */
bool compare_ovsubscription(ov_Subscription first, ov_Subscription second) {
	return first.id > second.id;
}

//! Add a new OVData record
/** @param ovdata The record to add
 */
BOOL InsertOVData(ov_data ovdata) {
	char buffer[500];
	int idx;
	sprintf(buffer, "%u", ovdata.id);
	int i = 0;
	int iShowLocation = SendMessage(hShowLocations, BM_GETCHECK, NULL, NULL) == BST_CHECKED ? 1 : 0;

	LVITEM lvI;
	lvI.mask = LVIF_TEXT | LVIF_STATE;
	lvI.iSubItem = i;
	lvI.state = 0;
	lvI.stateMask = 0;
	lvI.pszText = buffer;
	lvI.iItem = 0;
	i++;
  
	//Inserting item ID
	if (-1 != (idx = ListView_InsertItem(hData, &lvI))) {
		
		if (iShowLocation) {
			//Insert location
			sprintf(buffer, "%03x", ovdata.location);
			lvI.iSubItem = i;
			ListView_SetItem(hData, &lvI);
			i++;
		}
		

		//Insert date
		GetDateSince1997(ovdata.date, buffer);
		lvI.iSubItem = i;
		ListView_SetItem(hData, &lvI);
		i++;

		//Insert time
		sprintf(buffer, "%u:%02u", ovdata.time / 60, ovdata.time % 60);
		lvI.iSubItem = i;
		ListView_SetItem(hData, &lvI);
		i++;

		//Insert company
		GetCompanyName(ovdata.company, buffer);
		lvI.iSubItem = i;
		ListView_SetItem(hData, &lvI);
		i++;

		//Insert transfer
		GetTransfer(ovdata.transfer, buffer);
		lvI.iSubItem = i;
		ListView_SetItem(hData, &lvI);
		i++;

		//Insert vehicle
		sprintf(buffer, "ID: %u", ovdata.vehicleId);
		lvI.iSubItem = i;
		ListView_SetItem(hData, &lvI);
		i++;

		//Insert machine
		sprintf(buffer, "ID: %u", ovdata.poleid);
		lvI.iSubItem = i;
		ListView_SetItem(hData, &lvI);
		i++;

		//Insert ammount
		sprintf(buffer, "%u.%02u", ovdata.amount / 100, ovdata.amount % 100);
		lvI.iSubItem = i;
		ListView_SetItem(hData, &lvI);
		i++;

		//Insert station
		GetStationInfo(DatabaseFile, ovdata.company, ovdata.station, buffer);
		lvI.iSubItem = i;
		ListView_SetItem(hData, &lvI);
		i++;
		return TRUE;
	}
	return FALSE;
}

//! Add a new OVSubscription record
/** @param ovsubscription The record to add
 */
BOOL InsertOVSubscription(ov_Subscription ovsubscription) {
	char buffer[500];
	int idx;
	sprintf(buffer, "%u", ovsubscription.id);
	int i = 0;
	int iShowLocation = SendMessage(hShowLocations, BM_GETCHECK, NULL, NULL) == BST_CHECKED ? 1 : 0;

	LVITEM lvI;
	lvI.mask = LVIF_TEXT | LVIF_STATE;
	lvI.iSubItem = i;
	lvI.state = 0;
	lvI.stateMask = 0;
	lvI.pszText = buffer;
	lvI.iItem = 0;
	i++;
  
	//Inserting item ID
	if (-1 != (idx = ListView_InsertItem(hSubscriptions, &lvI))) {
		
		if (iShowLocation) {
			//Insert location
			sprintf(buffer, "%03x", ovsubscription.location);
			lvI.iSubItem = i;
			ListView_SetItem(hSubscriptions, &lvI);
			i++;
		}
		
		//Insert company
		GetCompanyName(ovsubscription.company, buffer);
		lvI.iSubItem = i;
		ListView_SetItem(hSubscriptions, &lvI);
		i++;

		//lvc.pszText = "Valid From";
		GetDateSince1997(ovsubscription.validFrom, buffer);
		lvI.iSubItem = i;
		ListView_SetItem(hSubscriptions, &lvI);
		i++;

		//lvc.pszText = "Valid To";
		GetDateSince1997(ovsubscription.validTo, buffer);
		lvI.iSubItem = i;
		ListView_SetItem(hSubscriptions, &lvI);
		i++;

		//lvc.pszText = "Subscription";
		GetSubscription(ovsubscription.company, ovsubscription.subscription, buffer);
		lvI.iSubItem = i;
		ListView_SetItem(hSubscriptions, &lvI);
		i++;
		return TRUE;
	}
	return FALSE;
}

//! Export ovdata to a file, set szFileName first!
void ExportData() {
	char buffer[2048];
	FILE *fWrite;

	fWrite = fopen(szFileName, "wb");

	fprintf(fWrite, "id;date;time;transferraw;transfer;amount;location;companyraw;company;stationraw;station\r\n");
	std::list<ov_data>::iterator it;
	for (it=allData.begin(); it!=allData.end(); ++it) {
	fprintf(fWrite, "%u", it->id); //id
	GetDateSince1997(it->date, buffer);
	fprintf(fWrite, ";%s", buffer); //date
	fprintf(fWrite, ";%u:%02u", it->time / 60, it->time % 60); //time
	fprintf(fWrite, ";%u", it->transfer);//transferraw
	GetTransfer(it->transfer, buffer);
	fprintf(fWrite, ";%s", buffer);//transfer
	fprintf(fWrite, ";%u", it->amount);//amount
	fprintf(fWrite, ";%03x", it->location);//location
	fprintf(fWrite, ";%u", it->company);//companyraw
	GetCompanyName(it->company, buffer);
	fprintf(fWrite, ";%s", buffer);//company
	fprintf(fWrite, ";%u", it->station);//stationraw
	GetStationInfo(DatabaseFile, it->company, it->station, buffer);
	fprintf(fWrite, ";%s\r\n", buffer);//station
	}

	fclose(fWrite);
}

void SetAmount(int value_1, int value_2) {
	char *buffer = (char*)malloc(100);
	sprintf(buffer, "Saldo: € %c%i.%02u, vorig saldo: € %c%i.%02u", 
		value_1 < 0 ? '-' : ' ',
		value_1 == 0 ? 0 : ((value_1 < 0 ? value_1 * -1 : value_1) / 100),
		value_1 == 0 ? 0 : ((value_1 < 0 ? value_1 * -1 : value_1) % 100),
		value_2 < 0 ? '-' : ' ',
		value_2 == 0 ? 0 : ((value_2 < 0 ? value_2 * -1 : value_2) / 100),
		value_2 == 0 ? 0 : ((value_2 < 0 ? value_2 * -1 : value_2) % 100)
	);
	SendMessage(hValue, WM_SETTEXT, 0, (LPARAM)buffer);
	free(buffer);
}

//! Analyse OV dump
/** @param buffer the dump to the file
 * @param size the size of the buffer
 */
void AnalyseData(unsigned char* buffer, int size) {
	if (size != 4096 && size != 64) return;
	unsigned char* bPoint;
	unsigned char* bLoop;
	int i, j;
	ov_data ovdata;
	ov_Subscription ovsubs;
	char UID[48];
	char products[500];
	std::list<ov_data>::iterator it;
	std::list<ov_Subscription>::iterator itSubs;
	bool hasBirthDate = false;
	bool duplicate = false;
	bool studentWeek = false;
	bool studentWeekend = false;
	int iClass = 0;
	unsigned int iClassFromID = 0;
	bool showDuplicate = SendMessage(hShowDuplicates, BM_GETCHECK, NULL, NULL) == BST_CHECKED;
	if (allData.size() > 0)
		allData.clear();

	if (allSubs.size() > 0)
		allSubs.clear();
	
	//Set card UID
	sprintf(UID, "Found MIFARE Classic %cK card with uid: %02x%02x%02x%02x", (size == 4096 ? '4' : '1'), buffer[0], buffer[1], buffer[2], buffer[3]);
	SetCardID(UID);

	//Check if it's a ov card
	if (4096 != size) return;

	//Loop through transactions
	for (int i = 32; i <= 34; i++) {
		bPoint = buffer + mfclassic_getsector(i);
		for (bLoop = bPoint; bLoop < bPoint + 0xF0; bLoop += 0x30) {
			if (0 != bLoop[0]) {
				OvcSubscription(bLoop, bLoop - buffer, 0, 0x30, &ovsubs);
				if (ovsubs.valid) {
					//Check if the item is already in the list
					allSubs.push_back(ovsubs);
				}
			}
		}
	}

	//Loop through products
	for (i = 35; i < 39; i++) {
		bPoint = buffer + mfclassic_getsector(i);
		for (bLoop = bPoint; bLoop < bPoint + 0xF0; bLoop += 0x20) {
			if (0 != bLoop[0]) {
				OvcClassicTransaction(bLoop, bLoop - buffer, 0, 0x20, &ovdata);
				if (ovdata.valid) {
					duplicate = false;
					if (!showDuplicate) {
						for (it=allData.begin(); it!=allData.end() && !duplicate; ++it) {
							duplicate = (it->date == ovdata.date && it->time == ovdata.time && it->id == ovdata.id);
						}
					}
					if (!duplicate) {
						allData.push_back(ovdata);
					}
				}
			}
		}
	}

	//Sort data
	allData.sort(compare_ovdata);
	allSubs.sort(compare_ovsubscription);

	//Insert OV data
	for (it=allData.begin(); it!=allData.end(); ++it)
		InsertOVData(*it);
	
	//Set listview column width to the content of the listview
	for (i = 0; i < 10; i++)
		ListView_SetColumnWidth(hData, i, -2);
	

	//Get current value on the card
	bPoint = buffer + 0xF90;
	int iIDa1 = ((bPoint[1] & 0x7F) << 5) | ((bPoint[2] >> 3) & 0x1F);
	int iIDa2 = ((bPoint[4] & 0x7F) << 9) | ((bPoint[5] & 0xFF) << 1) | ((bPoint[6] >> 7) & 0x01);
	int iIDa3 = ((bPoint[6] & 0x0F) << 12) | ((bPoint[7] & 0xFF) << 4) | ((bPoint[8] >> 4) & 0x0F);
	i = ((bPoint[9] & 0x03) << 13) | ((bPoint[10] & 0xFF) << 5) | ((bPoint[11] >> 3) & 0x1F);
	if (!(bPoint[9] & 0x04)) {
		i ^= 0x7FFF;
		i = i * -1;
	}

	bPoint = buffer + 0xFA0;
	int iIDb1 = ((bPoint[1] & 0x7F) << 5) | ((bPoint[2] >> 3) & 0x1F);
	int iIDb2 = ((bPoint[4] & 0x7F) << 9) | ((bPoint[5] & 0xFF) << 1) | ((bPoint[6] >> 7) & 0x01);
	int iIDb3 = ((bPoint[6] & 0x0F) << 12) | ((bPoint[7] & 0xFF) << 4) | ((bPoint[8] >> 4) & 0x0F);
	j = ((bPoint[9] & 0x03) << 13) | ((bPoint[10] & 0xFF) << 5) | ((bPoint[11] >> 3) & 0x1F);
	if (!(bPoint[9] & 0x04)) {
		j ^= 0x7FFF;
		j = j * -1;
	}
	SetAmount(iIDb3 > iIDa3 ? j : i, iIDb3 > iIDa3 ? i : j);
	
	//Get expiration date
	bPoint = buffer + 0x010;
	i = ((bPoint[11] & 0x03) << 12) | ((bPoint[12] & 0xFF) << 4) | ((bPoint[13] >> 4) & 0x0F);

	GetDateSince1997(i, UID);

	//Get birthdate
	bPoint = buffer + 0x580;

	if (0x0E == bPoint[0] && 0x02 == bPoint[1] && 0x94 == bPoint[2]) { //Has a product
		hasBirthDate = (bPoint[13] & 0x02); //Has a birthdate
	}

	sprintf(products, "Kaart geldig tot %s", UID);
	if (hasBirthDate)
		sprintf(products, "%s, geboortedatum %x%x-%x-%x", products, bPoint[14], bPoint[15], bPoint[16], bPoint[17]);

	bPoint = buffer + 0xFB0;
	i = 0;
	i = ((unsigned char)((bPoint[1] & 0x03) << 10) | (unsigned char)((bPoint[2] & 0xFF) << 2) | (unsigned char)((bPoint[3] >> 6) & 0x03));
	bPoint = buffer + 0xFD0;
	j = 0;
	j = ((unsigned char)((bPoint[1] & 0x03) << 10) | (unsigned char)((bPoint[2] & 0xFF) << 2) | (unsigned char)((bPoint[3] >> 6) & 0x03));

	if (i > j) {
		bPoint = buffer + 0xFB0;
	} else {
		bPoint = buffer + 0xFD0;
	}

	i = (unsigned char)(bPoint[19] & 0x0F);
	j = i < 7 ? (0xB00 + i * 0x20) : (0xC00 + (i - 7) * 0x20);

	sprintf(products, "%s, laatste actie op %03x", products, j);

	i = (unsigned char)(bPoint[30] & 0x0F);
	j = i == 1 ? 0xe80 : i == 6 ? 0xea0 : 0xec0;
	sprintf(products, "%s, laatste opwaardering op %03x", products, j);

	SetStatusmessage(products);
	
	//Get subscriptions
	for (itSubs=allSubs.begin(); itSubs!=allSubs.end(); ++itSubs) {
		InsertOVSubscription(*itSubs);
	}

	for (i = 0; i < 8; i++)
		ListView_SetColumnWidth(hSubscriptions, i, -2);

	//Fix the disappearing listview bug
	InvalidateRect(hMain,NULL,true);
}

//! Load in a dump from a file, NOTE set the filename to szFileName
/** @param parm the parameters that got send throught the threadstart
 */
static void StartWriting(void *parm) {
	char *filename = szFileName;
	FILE * dumpFile;
	long filelength;
	bool bKeyA = SendMessage(hUseKeyA, BM_GETCHECK, NULL, NULL) == BST_CHECKED;
	bool bKeyB = SendMessage(hUseKeyB, BM_GETCHECK, NULL, NULL) == BST_CHECKED;
	bool bWritekeys = SendMessage(hWritekeys, BM_GETCHECK, NULL, NULL) == BST_CHECKED;
	int iSelectedDevice = SendMessage(hWritekeys, CB_GETCURSEL, NULL, NULL);
	if (CB_ERR == iSelectedDevice) {
		MessageBox(NULL, "Select a device to write to!", "Error!", MB_ICONEXCLAMATION | MB_OK);
	}
	nfc_device_desc_t device;
	memcpy(&device, &pnddDevices[iSelectedDevice], sizeof(nfc_device_desc_t));

	if (dumpFile = fopen(filename, "rb")) {
		fseek(dumpFile, 0, SEEK_END);
		filelength = ftell(dumpFile);
		if (4096 == filelength || 1024 == filelength) {
			fseek(dumpFile, 0, SEEK_SET);
			fread(lastDump, 1, filelength, dumpFile);
			fclose(dumpFile);
			WriteCard(&device, startDir, lastDump, 4096, bKeyA, bKeyB, bWritekeys, SetSectorStatus, SetStatusmessage, SetCardID);
		} else {
			fclose(dumpFile);
			MessageBox(NULL, "Dump file is not in the correct size!", "Error!", MB_ICONEXCLAMATION | MB_OK);
		}
	} else {
		MessageBox(NULL, "Could not open dump file!", "Error!", MB_ICONEXCLAMATION | MB_OK);
	}
}

//! Load in a dump from a file, NOTE set the filename to szFileName
/** @param parm the parameters that got send throught the threadstart
 */
static void StartReadingFile(void *parm) {
	char *filename = szFileName;
	FILE * dumpFile;
	long filelength;

	if (dumpFile = fopen(filename, "rb")) {
		fseek(dumpFile, 0, SEEK_END);
		filelength = ftell(dumpFile);
		if (4096 == filelength) {
			fseek(dumpFile, 0, SEEK_SET);
			fread(lastDump, 1, filelength, dumpFile);
			fclose(dumpFile);
			lastDumpSize = 4096;
			AnalyseData(lastDump, 4096);
		} else {
			fclose(dumpFile);
			MessageBox(NULL, "Dump file is not in the correct size!", "Error!", MB_ICONEXCLAMATION | MB_OK);
		}
	} else {
		MessageBox(NULL, "Could not open dump file!", "Error!", MB_ICONEXCLAMATION | MB_OK);
	}
}

static void StartReading(void *parm) {
	if (!readingCard) {
		readingCard = true;
		SendMessage(hReadData, WM_SETTEXT, 0, (LPARAM)"&Stop reading");
		//int ReadCard(int sets, char *keyDir, char *buffer, int buffersize, int skipToSector, bool keyA, bool keyB, void (*UpdateSectorStatus)(char, int, byte_t), void (*UpdateStatusMessage)(char *status), void (*SetCardInfo)(char *status));
		int iSets = SendMessage(hNumberOfSets, TBM_GETPOS, 0, 0);
		int skipToSector = (SendMessage(hOVCard, BM_GETCHECK, NULL, NULL) == BST_CHECKED) ? 22 : 1;
		bool bKeyA = SendMessage(hUseKeyA, BM_GETCHECK, NULL, NULL) == BST_CHECKED;
		bool bKeyB = SendMessage(hUseKeyB, BM_GETCHECK, NULL, NULL) == BST_CHECKED;
		int iSelectedDevice = SendMessage(hReader, CB_GETCURSEL, NULL, NULL);
		if (CB_ERR == iSelectedDevice) {
			MessageBox(NULL, "Select a device to read from!", "Error!", MB_ICONEXCLAMATION | MB_OK);
			SendMessage(hReadData, WM_SETTEXT, 0, (LPARAM)"&Read data (Reader)");
			readingCard = false;
			return;
		}
		nfc_device_desc_t device;
		memcpy(&device, &pnddDevices[iSelectedDevice], sizeof(nfc_device_desc_t));

		std::list<performance> lPerf;
		std::list<performance>::iterator itPerf;
		ULONGLONG ullStart = GetTickCount();
		lastDumpSize = ReadCard(&device, &lPerf, iSets, startDir, lastDump, 4096, skipToSector, bKeyA, bKeyB, SetSectorStatus, SetStatusmessage, SetCardID);
		ULONGLONG ullEnd = GetTickCount();
		performance pTotal;
		pTotal.duration = ullEnd - ullStart;
		pTotal.keyType = ' ';
		pTotal.probe = -1;
		pTotal.sector = -1;
		pTotal.set = -1;
	

		char statisticsMessage[5000];
		if (lastDumpSize == 0) {
			sprintf(statisticsMessage, "No statistics available, time till error: %llu", pTotal.duration);
		}
		else {
			ULONGLONG uMinSector = 0xFFFFFFFF << 32 | 0xFFFFFFFF;
			ULONGLONG uMaxSector = 0;
			ULONGLONG uSectorCount = 0;

			ULONGLONG uMinProbe = 0xFFFFFFFF << 32 | 0xFFFFFFFF;
			ULONGLONG uMaxProbe = 0;
			ULONGLONG uProbeCount = 0;

			ULONGLONG uMinSet = 0xFFFFFFFF << 32 | 0xFFFFFFFF;
			ULONGLONG uMaxSet = 0;
			ULONGLONG uSetCount = 0;

			ULONGLONG uMinSectorB = 0xFFFFFFFF << 32 | 0xFFFFFFFF;
			ULONGLONG uMaxSectorB = 0;
			ULONGLONG uSectorCountB = 0;

			ULONGLONG uMinProbeB = 0xFFFFFFFF << 32 | 0xFFFFFFFF;
			ULONGLONG uMaxProbeB = 0;
			ULONGLONG uProbeCountB = 0;

			ULONGLONG uMinSetB = 0xFFFFFFFF << 32 | 0xFFFFFFFF;
			ULONGLONG uMaxSetB = 0;
			ULONGLONG uSetCountB = 0;

			for (itPerf = lPerf.begin(); itPerf != lPerf.end(); ++itPerf) {
				if (itPerf->keyType == 'A') {
					if (itPerf->set != -1) {
						//it's a set
						if (itPerf->duration < uMinSet)
							uMinSet = itPerf->duration;
						if (itPerf->duration > uMaxSet)
							uMaxSet = itPerf->duration;

						uSetCount++;
					}
					else if (itPerf->probe != -1) {
						//it's a probe
						if (itPerf->duration < uMinProbe)
							uMinProbe = itPerf->duration;
						if (itPerf->duration > uMaxProbe)
							uMaxProbe = itPerf->duration;

						uProbeCount++;
					}
					else if (itPerf->sector != -1) {
						//it's a sector
						if (itPerf->duration < uMinSector)
							uMinSector = itPerf->duration;
						if (itPerf->duration > uMaxSector)
							uMaxSector = itPerf->duration;

						uSectorCount++;
					}
				
				}
				else if (itPerf->keyType == 'B') {
					if (itPerf->set != -1) {
						//it's a set
						if (itPerf->duration < uMinSetB)
							uMinSetB = itPerf->duration;
						if (itPerf->duration > uMaxSetB)
							uMaxSetB = itPerf->duration;

						uSetCountB++;
					}
					else if (itPerf->probe != -1) {
						//it's a probe
						if (itPerf->duration < uMinProbeB)
							uMinProbeB = itPerf->duration;
						if (itPerf->duration > uMaxProbeB)
							uMaxProbeB = itPerf->duration;

						uProbeCountB++;
					}
					else if (itPerf->sector != -1) {
						//it's a sector
						if (itPerf->duration < uMinSectorB)
							uMinSectorB = itPerf->duration;
						if (itPerf->duration > uMaxSectorB)
							uMaxSectorB = itPerf->duration;

						uSectorCountB++;
					}
				}
			}
		
			//Stupid hack
			sprintf(statisticsMessage, "Statistics Card:\r\nTotal time: %I64u", pTotal.duration);
			sprintf(statisticsMessage, "%sms\r\n\r\nKey A:\r\n", statisticsMessage);
			if (uSectorCount > 0) {
				sprintf(statisticsMessage, "%sSector count: %u\r\n-Minimum time: ", statisticsMessage, uSectorCount);
				sprintf(statisticsMessage, "%s%I64u", statisticsMessage, uMinSector);
				sprintf(statisticsMessage, "%sms\r\n-Maximum time: ", statisticsMessage);
				sprintf(statisticsMessage, "%s%I64u", statisticsMessage, uMaxSector);
				sprintf(statisticsMessage, "%sms\r\n\r\n", statisticsMessage);
			}
			if (uProbeCount > 0) {
				sprintf(statisticsMessage, "%sProbe count: %u\r\n-Minimum time: ", statisticsMessage, uProbeCount);
				sprintf(statisticsMessage, "%s%I64u", statisticsMessage, uMinProbe);
				sprintf(statisticsMessage, "%sms\r\n-Maximum time: ", statisticsMessage);
				sprintf(statisticsMessage, "%s%I64u", statisticsMessage, uMaxProbe);
				sprintf(statisticsMessage, "%sms\r\n\r\n", statisticsMessage);
			}
			if (uSetCount > 0) {
				sprintf(statisticsMessage, "%sProbe count: %u\r\n-Minimum time: ", statisticsMessage, uSetCount);
				sprintf(statisticsMessage, "%s%I64u", statisticsMessage, uMinSet);
				sprintf(statisticsMessage, "%sms\r\n-Maximum time: ", statisticsMessage);
				sprintf(statisticsMessage, "%s%I64u", statisticsMessage, uMaxSet);
				sprintf(statisticsMessage, "%sms\r\n\r\n", statisticsMessage);
			}
			sprintf(statisticsMessage, "%sKey B:\r\n", statisticsMessage);
			if (uSectorCountB > 0) {
				sprintf(statisticsMessage, "%sSector count: %u\r\n-Minimum time: ", statisticsMessage, uSectorCountB);
				sprintf(statisticsMessage, "%s%I64u", statisticsMessage, uMinSectorB);
				sprintf(statisticsMessage, "%sms\r\n-Maximum time: ", statisticsMessage);
				sprintf(statisticsMessage, "%s%I64u", statisticsMessage, uMaxSectorB);
				sprintf(statisticsMessage, "%sms\r\n\r\n", statisticsMessage);
			}
			if (uProbeCountB > 0) {
				sprintf(statisticsMessage, "%sProbe count: %u\r\n-Minimum time: ", statisticsMessage, uProbeCountB);
				sprintf(statisticsMessage, "%s%I64u", statisticsMessage, uMinProbeB);
				sprintf(statisticsMessage, "%sms\r\n-Maximum time: ", statisticsMessage);
				sprintf(statisticsMessage, "%s%I64u", statisticsMessage, uMaxProbeB);
				sprintf(statisticsMessage, "%sms\r\n\r\n", statisticsMessage);
			}
			if (uSetCountB > 0) {
				sprintf(statisticsMessage, "%sProbe count: %u\r\n-Minimum time: ", statisticsMessage, uSetCountB);
				sprintf(statisticsMessage, "%s%I64u", statisticsMessage, uMinSetB);
				sprintf(statisticsMessage, "%sms\r\n-Maximum time: ", statisticsMessage);
				sprintf(statisticsMessage, "%s%I64u", statisticsMessage, uMaxSetB);
				sprintf(statisticsMessage, "%sms\r\n\r\n", statisticsMessage);
			}
			SendMessage(hStatistics, WM_SETTEXT, 0, (LPARAM)statisticsMessage);

			//Dump File
			bool bDumpToFile = SendMessage(hDumpToFile, BM_GETCHECK, NULL, NULL) == BST_CHECKED;
			if (bDumpToFile) {
				char filename[1000];
				FILE *pfDump;
				SYSTEMTIME lt;
				GetLocalTime(&lt);

				if (lastDumpSize == 1024 || lastDumpSize == 4096) {
					sprintf(filename, "%s/dumpfile %02x%02x%02x%02x (%04d-%02d-%02d %02d_%02d_%02d) %s.dump", dumpToFileDir, lastDump[0], lastDump[1], lastDump[2], lastDump[3], lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond, lastDumpSize == 4096 ? "4K" : "1K");
				}
				else if (lastDumpSize = 64) {
					sprintf(filename, "%s/dumpfile %02x%02x%02x%02x (%04d-%02d-%02d %02d_%02d_%02d) UL.dump", dumpToFileDir, lastDump[3], lastDump[2], lastDump[1], lastDump[0], lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond);
				}

				if (!(pfDump = fopen(filename, "wb"))) {
					SetStatusmessage("status: Could not open the file for dump.");
					EnableWindow(hReadData, TRUE);
					SendMessage(hReadData, WM_SETTEXT, 0, (LPARAM)"&Read data (Reader)");
					readingCard = false;
					return;
				}

				fwrite(lastDump, 1, lastDumpSize, pfDump);
				fclose(pfDump);
			}

			if (SendMessage(hNonOVCard, BM_GETCHECK, NULL, NULL) == BST_CHECKED) {
				SendMessage(hValue, WM_SETTEXT, 0, (LPARAM)"Credit: €0,00");
			}
			else {
				AnalyseData(lastDump, lastDumpSize);
			}
		}

	

		SendMessage(hReadData, WM_SETTEXT, 0, (LPARAM)"&Read data (Reader)");
		readingCard = false;
	}
	else {
		stopreadingcard = true;
	}
}

//! Handle the WM_COMMAND, button click, trackbar
/** @param hwnd The HWND from the WndProc function
 * @param wParam The WPARAM from the WndProc function
 */
void Handle_WM_COMMAND(HWND hwnd, WPARAM wParam) {
	int iID = LOWORD(wParam);
	OPENFILENAME ofn;
	int iMessageboxResult;
	BROWSEINFO bi = { 0 };
	LPITEMIDLIST pidl;

	switch (iID) {
	case hmUseHotkeyKey:
		Handle_UsehotkeyKeyChange();
		SaveSettings();
		break;
	case hmUseHotkey:
		Handle_UsehotkeyChange();
		SaveSettings();
		break;
	case hmNonOVCard: //Non-OV Card
	case hmOVCard: //OV Card
	case hmOVCardEverything: //OV Card - Read Everything
		Handle_TypeofcardChange();
		SaveSettings();
		break;
	case hmShowLocations: //Show Location
		InitListViewColumnsAbonnementen(hSubscriptions);
		InitListViewColumnsReis(hData);
		SaveSettings();
		ListView_DeleteAllItems(hData);
		ListView_DeleteAllItems(hSubscriptions);
		AnalyseData(lastDump, lastDumpSize);
		break;
	case hmShowDuplicates: //Show duplicates
		SaveSettings();
		ListView_DeleteAllItems(hData);
		ListView_DeleteAllItems(hSubscriptions);
		AnalyseData(lastDump, lastDumpSize);
		break;
	case hmUseKeyB: //Use Key B
		Handle_UseKeyBChange();
		SaveSettings();
		break;
	case hmUseKeyA: //Use Key A
		Handle_UseKeyAChange();
		SaveSettings();
		break;
	case hmDumpToFile: //Dump to file
		Handle_DumpToFileChange();
		SaveSettings();
		break;
	case hmReadData: //Read data (Reader)
		ListView_DeleteAllItems(hData);
		ListView_DeleteAllItems(hSubscriptions);
		_beginthread(StartReading, 0, hMain );
		break;
	case hmReadFile: //Read data (file)
		
					
		szFileName[0] = '\0';
		ZeroMemory(&ofn, sizeof(ofn));

		ofn.lStructSize = sizeof(ofn);
		ofn.hwndOwner = hwnd;
		ofn.lpstrFilter = "Dump Files (*.dump)\0*.dump\0All Files (*.*)\0*.*\0";
		ofn.lpstrFile = szFileName;
		ofn.nMaxFile = MAX_PATH;
		ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST;
		ofn.lpstrDefExt = "dump";

		if (GetOpenFileName(&ofn)) {
			ListView_DeleteAllItems(hData);
			ListView_DeleteAllItems(hSubscriptions);
			_beginthread(StartReadingFile, 0, hMain);
		}
		break;
	case hmExport: //Export (OV)
		szFileName[0] = '\0';
		ZeroMemory(&ofn, sizeof(ofn));

		ofn.lStructSize = sizeof(ofn);
		ofn.hwndOwner = hwnd;
		ofn.lpstrFilter = "Comma Sepperated Values (*.csv)\0*.csv\0";
		ofn.lpstrFile = szFileName;
		ofn.nMaxFile = MAX_PATH;
		ofn.Flags = OFN_EXPLORER | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
		ofn.lpstrDefExt = "dump";
		if (GetSaveFileName(&ofn))
			ExportData();
				
		break;
	case hmSelectDirectoryDump: //Select Dump to directory
		
		
    bi.lpszTitle = "Pick a Directory";
    pidl = SHBrowseForFolder ( &bi );
    if ( pidl != 0 )
    {
        // get the name of the folder
        TCHAR path[MAX_PATH];
        if ( SHGetPathFromIDList ( pidl, path ) )
        {
            sprintf(dumpToFileDir, "%s", path);
						SendMessage(hDumpDirectory, WM_SETTEXT, 0, (LPARAM)dumpToFileDir);
        }

        // free memory used
        IMalloc * imalloc = 0;
        if ( SUCCEEDED( SHGetMalloc ( &imalloc )) )
        {
            imalloc->Free ( pidl );
            imalloc->Release ( );
        }
    }
		SaveSettings();
		break;
	case hmWritedata: //Write dump
		iMessageboxResult = MessageBox(NULL, "Door op JA te klikken bevestigd U dat de kaart die U beschrijft geen OV-chipkaart is.\nIndien dit wel een ov-chipkaart is bent U zelf verantwoordelijk voor de eventuele gevolgen.", "MFOC GUI", MB_ICONEXCLAMATION | MB_YESNO);
		if (iMessageboxResult == IDYES) {
			szFileName[0] = '\0';
			ZeroMemory(&ofn, sizeof(ofn));

			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = hwnd;
			ofn.lpstrFilter = "Dump Files (*.dump)\0*.dump\0All Files (*.*)\0*.*\0";
			ofn.lpstrFile = szFileName;
			ofn.nMaxFile = MAX_PATH;
			ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST;
			ofn.lpstrDefExt = "dump";

			if (GetOpenFileName(&ofn)) {
				ListView_DeleteAllItems(hData);
				ListView_DeleteAllItems(hSubscriptions);
				_beginthread(StartWriting, 0, hMain);
			}
		}
		break;

	}
}

//! Handle the drawing
/** @param hwnd The HWND from the WndProc function
 */
void Handle_WM_PAINT(HWND hwnd) {
	RECT clientRect;
	InvalidateRect(hwnd,NULL,true);

	PAINTSTRUCT ps;
	HDC hdc = BeginPaint(hwnd, &ps);
	GetClientRect(hwnd, &clientRect);
			
	Graphics graphics(hdc);
	graphics.DrawImage(ovImg, clientRect.right - clientRect.left - 12 - 64, 12, 64, 64);

	EndPaint(hwnd, &ps);
}

//! Handle the WM_HSCROLL message
void Handle_WM_HSCROLL() {
	int i = SendMessage(hNumberOfSets, TBM_GETPOS, 0, 0);
	char BUFFER[15];
	sprintf(BUFFER, "Sets: %i", i);
	SendMessage(hNumberOfSetsL, WM_SETTEXT, 0, (LPARAM)&BUFFER);
}

//! Handle the WM_GETMINMAXINFO, minimal size
/** @param lParam The LPARAM from the WndProc function
 */
void Handle_WM_GETMINMAXINFO(LPARAM lParam) {
	LPMINMAXINFO pMMI = (LPMINMAXINFO)lParam;
	pMMI->ptMinTrackSize.x = 800;
	pMMI->ptMinTrackSize.y = 600;
}

//! Handle resizing
/** @param hwnd The HWND from the WndProc function
 */
void Handle_WM_SIZE(HWND hwnd) {
	RECT clientRect;
	GetClientRect(hwnd, &clientRect);
	SetWindowPos(hMainTabControl, NULL, 0, 0, clientRect.right - clientRect.left - 24, clientRect.bottom - clientRect.top - 91, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER | SWP_NOZORDER);
	RECT crTab;
	GetClientRect(hMainTabControl, &crTab);
	SendMessage(hMainTabControl, TCM_ADJUSTRECT, NULL, (LPARAM)&crTab);
	crTab.left += iTabLeft;
	crTab.right += iTabLeft - 2;
	crTab.top += iTabTop;
	crTab.bottom += iTabTop - 5;

	SetWindowPos(hCardID, NULL, 0, 0, clientRect.right - clientRect.left - 64 - 12 - 12 - 6, iHeiCardID, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER | SWP_NOZORDER);
	SetWindowPos(hStatus, NULL, 0, 0, clientRect.right - clientRect.left - 64 - 12 - 12 - 6, iHeiStatus, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER | SWP_NOZORDER);
	SetWindowPos(hValue, NULL, 0, 0, clientRect.right - clientRect.left - 64 - 12 - 12 - 6, iHeiValue, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER | SWP_NOZORDER);

	SetWindowPos(hDumpDirectory, NULL, 0, 0, clientRect.right - clientRect.left - iDumpDirectoryLeft - 24, iDumpDirectoryHeight, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER | SWP_NOZORDER);
	SetWindowPos(hOverlay, NULL, 0, 0, crTab.right - crTab.left, crTab.bottom - crTab.top, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER | SWP_NOZORDER);

	SetWindowPos(hStatistics, NULL, 0, 0, crTab.right - crTab.left, crTab.bottom - crTab.top, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER | SWP_NOZORDER);
	SetWindowPos(hData, NULL, 0, 0, crTab.right - crTab.left, crTab.bottom - crTab.top, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER | SWP_NOZORDER);
	SetWindowPos(hSubscriptions, NULL, 0, 0, crTab.right - crTab.left, crTab.bottom - crTab.top, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOOWNERZORDER | SWP_NOZORDER);
}

//! Set the sector status for a specified sector
/** @param type The type of key (A or B)
 * @param sector The sector to set
 * @param status The sector status, 0 for idle not cracked, 1 for busy with sector, 2 for cracked
 */
void SetSectorStatus(char type, int sector, byte_t status) {
	HWND hSector;
	if ('A' == type || 'B' == type) {
		hSector = GetDlgItem(hMain, (type == 'A' ? 200 : 300) + sector);
		if (hSector) {
			switch (status) {
				case 1:
					SendMessage(hSector, BM_SETCHECK, BST_INDETERMINATE, 0);
					break;
				case 2:
					SendMessage(hSector, BM_SETCHECK, BST_CHECKED, 0);
					break;
				default:
					SendMessage(hSector, BM_SETCHECK, BST_UNCHECKED, 0);
					break;
			}
		}
	}
}

//! An application-defined function that processes messages sent to a window. The WNDPROC type defines a pointer to this callback function.
/** @param hwnd A handle to the window.
 * @param msg The message
 * @param wParam Additional message information. The contents of this parameter depend on the value of the msg parameter.
 * @param lParam Additional message information. The contents of this parameter depend on the value of the msg parameter.
 * @return The return value is the result of the message processing and depends on the message sent.
 */
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	switch (msg) {
	case WM_HOTKEY:
		Handle_WM_HOTKEY(wParam);
		break;
	case WM_SIZE:
		Handle_WM_SIZE(hwnd);
		break;
	case WM_GETMINMAXINFO:
		Handle_WM_GETMINMAXINFO(lParam);
		break;
	case WM_HSCROLL:
		Handle_WM_HSCROLL();
		SaveSettings();
		break;
	case WM_PAINT:
		Handle_WM_PAINT(hwnd);
		break;
	case WM_COMMAND:
		Handle_WM_COMMAND(hwnd, wParam);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	case WM_CREATE:
		Handle_WM_CREATE(hwnd);
		break;
	case WM_NOTIFY:
		return Handle_WM_NOTIFY(hwnd, lParam);
	case WM_SHOWWINDOW:
		LoadSettings();
		Update_All_Controls();
		DisplayTab(0);
		break;
	case WM_DEVICECHANGE:
		LoadReaders();
		break;
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
	return 0;
}