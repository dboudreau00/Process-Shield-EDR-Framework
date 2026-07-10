#pragma once

//
// Shared definitions between the ShieldFilter minifilter and the user-mode
// MinifilterClient.cs. The SHIELD_MESSAGE layout MUST stay byte-identical to the
// managed struct (sequential, default packing): UINT32, UINT32, WCHAR[260].
//

#define SHIELD_PORT_NAME    L"\\ShieldFilterPort"
#define SHIELD_MAX_PATH     260
#define SHIELD_MAX_ENTRIES  64

typedef enum _SHIELD_COMMAND {
    ShieldSetBlocking      = 1,   // Flag = 0/1
    ShieldAddSensitivePath = 2,   // Path = fragment to match (case-insensitive)
    ShieldClearPolicy      = 3
} SHIELD_COMMAND;

typedef struct _SHIELD_MESSAGE {
    UINT32 Command;
    UINT32 Flag;
    WCHAR  Path[SHIELD_MAX_PATH];
} SHIELD_MESSAGE, *PSHIELD_MESSAGE;
