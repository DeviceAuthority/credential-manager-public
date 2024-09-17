#pragma once

// Internal name of the service
#define SERVICE_NAME            TEXT("DACredMgrSvc")
// Displayed name of the service
#define SERVICE_DISPLAY_NAME    TEXT("Device Authority Credential Manager")
// Description of the service
#define SERVICE_DESCRIPTION     TEXT("Device Authority Credential Manager is an agent responsible for registering, authenticating, and pulling down assets/credentials from KeyScaler for the host device")
// Service desired access
#define SERVICE_DESIRED_ACCESS  SERVICE_ALL_ACCESS   // SERVICE_QUERY_STATUS
// Service start options
#define SERVICE_START_TYPE      SERVICE_DEMAND_START // SERVICE_AUTO_START
// List of service dependencies - "dep1\0dep2\0\0"
#define SERVICE_DEPENDENCIES    TEXT("")
// The name of the account under which the service should run
#define SERVICE_ACCOUNT         TEXT("NT AUTHORITY\\LocalService")
// The password to the service account name 
#define SERVICE_PASSWORD        NULL

// The following are message definitions.
//
//  Values are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_SYSTEM                  0x0
#define FACILITY_STUBS                   0x3
#define FACILITY_RUNTIME                 0x2
#define FACILITY_IO_ERROR_CODE           0x4

//
// Define the severity codes
//
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_ERROR            0x3

//
// MessageId: SVC_ERROR
//
// MessageText:
//
//  An error has occurred (%2).
//  
//
#define SVC_ERROR                        ((DWORD)0xC0020001L)
