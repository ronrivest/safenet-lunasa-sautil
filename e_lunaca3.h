/* $Source: ossl_vob/sautil/e_lunaca3.h $ $Revision: 1.1 $ */
/*****************************************************************************
*                                                                            *
*   Copyright (C) 2009 SafeNet, Inc. All rights reserved.                    *
*   See the attached file "SFNT_Legal.pdf" for the license terms and         *
*   conditions that govern the use of this software.                         *
*                                                                            *
*   Installing, copying, or otherwise using this software indicates your     *
*   acknowledgement that you have read the license and agree to be bound     *
*   by and comply with all of its terms and conditions.                      *
*                                                                            *
*   If you do not wish to accept these terms and conditions,                 *
*   DO NOT OPEN THE FILE OR USE THE SOFTWARE.                                *
*                                                                            *
******************************************************************************/

#ifndef header_e_lunaca3_h
#define header_e_lunaca3_h

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************/

/* P11 data structures are packed on Windows platform only. */
#if defined(WIN32) || defined(_WIN32)
#pragma pack(push, e_lunaca3_h, 1)
#define CK_ENTRY  __declspec(dllexport)
/* #error "BUG: WIN32 defined!" */
#else
#define CK_ENTRY  /*empty*/
/* #error "BUG: WIN32 not defined!" */
#endif

/*****************************************************************************/

/* Miscellaneous */
#ifndef FALSE
#define FALSE  (0)
#endif

#ifndef TRUE
#define TRUE  (1)
#endif

#define CK_PTR  *
#define CK_POINTER  *
#define NULL_PTR  (0)
#define CK_INVALID_HANDLE  (0)

/* Error codes */
#define CKR_OK                               0x00000000
#define CKR_SLOT_ID_INVALID                  0x00000003
#define CKR_GENERAL_ERROR                    0x00000005
#define CKR_ATTRIBUTE_VALUE_INVALID          0x00000013
#define CKR_DEVICE_ERROR                     0x00000030
#define CKR_BUFFER_TOO_SMALL                 0x00000150

/* User types */
#define CKU_SO                         0
#define CKU_USER                       1

/* Mechanism types */
#define CKM_RSA_PKCS_KEY_PAIR_GEN      0x00000000
#define CKM_RSA_PKCS                   0x00000001
#define CKM_RSA_X_509                  0x00000003
#define CKM_SHA1_RSA_PKCS              0x00000006
#define CKM_RSA_X9_31                  0x0000000B
#define CKM_SHA1_RSA_X9_31             0x0000000C
#define CKM_DSA_KEY_PAIR_GEN           0x00000010
#define CKM_DSA                        0x00000011
#define CKM_DES3_KEY_GEN               0x00000131
#define CKM_DES3_CBC                   0x00000133
#define CKM_SHA_1                      0x00000220

#define CKM_ECDSA_KEY_PAIR_GEN         0x00001040 /* deprecated */
#define CKM_EC_KEY_PAIR_GEN            0x00001040
#define CKM_ECDSA                      0x00001041
#define CKM_ECDSA_SHA1                 0x00001042

/* OpenSession flags */
#define CKF_RW_SESSION                 0x0002 
#define CKF_SERIAL_SESSION             0x0004 

/* SessionInfo Flags */
#define CKF_LOGIN_REQUIRED             0x0004
                     
/* Object types */
#define CKO_DATA                   0x00000000 
#define CKO_CERTIFICATE            0x00000001
#define CKO_PUBLIC_KEY             0x00000002
#define CKO_PRIVATE_KEY            0x00000003
#define CKO_SECRET_KEY             0x00000004
#define CKO_VENDOR_DEFINED         0x80000000

/* Some attribute types */
#define CKA_CLASS                  0x0000
#define CKA_TOKEN                  0x0001
#define CKA_PRIVATE                0x0002
#define CKA_LABEL                  0x0003
#define CKA_APPLICATION            0x0010
#define CKA_VALUE                  0x0011
#define CKA_CERTIFICATE_TYPE       0x0080
#define CKA_ISSUER                 0x0081
#define CKA_SERIAL_NUMBER          0x0082   
#define CKA_START_DATE_OLD_XXX     0x0083 
#define CKA_END_DATE_OLD_XXX       0x0084 
#define CKA_KEY_TYPE               0x0100
#define CKA_SUBJECT                0x0101
#define CKA_ID                     0x0102
#define CKA_SENSITIVE              0x0103   
#define CKA_ENCRYPT                0x0104
#define CKA_DECRYPT                0x0105
#define CKA_WRAP                   0x0106
#define CKA_UNWRAP                 0x0107
#define CKA_SIGN                   0x0108
#define CKA_SIGN_RECOVER           0x0109
#define CKA_VERIFY                 0x010A
#define CKA_VERIFY_RECOVER         0x010B
#define CKA_DERIVE                 0x010C
#define CKA_START_DATE             0x0110
#define CKA_END_DATE               0x0111
#define CKA_MODULUS                0x0120
#define CKA_MODULUS_BITS           0x0121
#define CKA_PUBLIC_EXPONENT        0x0122
#define CKA_PRIVATE_EXPONENT       0x0123
#define CKA_PRIME_1                0x0124
#define CKA_PRIME_2                0x0125
#define CKA_EXPONENT_1             0x0126
#define CKA_EXPONENT_2             0x0127
#define CKA_COEFFICIENT            0x0128
#define CKA_PRIME                  0x0130
#define CKA_SUBPRIME               0x0131
#define CKA_BASE                   0x0132
#define CKA_VALUE_BITS             0x0160
#define CKA_VALUE_LEN              0x0161
#define CKA_EXTRACTABLE            0x0162
#define CKA_LOCAL                  0x0163
#define CKA_NEVER_EXTRACTABLE      0x0164
#define CKA_ALWAYS_SENSITIVE       0x0165
#define CKA_MODIFIABLE             0x0170
#define CKA_ECDSA_PARAMS           0x0180 /* deprecated */
#define CKA_EC_PARAMS              0x0180
#define CKA_EC_POINT               0x0181

#define CKA_VENDOR_DEFINED         0x80000000
#define CKA_FINGERPRINT_SHA1	   (CKA_VENDOR_DEFINED | 0x0002)


/* Key types */
#define CKK_RSA                    0x00000000
#define CKK_DSA                    0x00000001
#define CKK_DH                     0x00000002
#define CKK_ECDSA                  0x00000003 /* deprecated */
#define CKK_EC                     0x00000003
#define CKK_DES3                   0x00000015
#define CKK_AES                    0x0000001F
#define CKK_VENDOR_DEFINED         0x80000000


/* Token States */   
#define CKS_RO_PUBLIC_SESSION  (0)
#define CKS_RO_USER_FUNCTIONS  (1)
#define CKS_RW_PUBLIC_SESSION  (2)
#define CKS_RW_USER_FUNCTIONS  (3)
#define CKS_RW_SO_FUNCTIONS    (4)


/* Data types */
typedef unsigned char                  CK_BYTE;
typedef CK_BYTE                        CK_BBOOL;
typedef unsigned long int              CK_USHORT;
typedef unsigned long int              CK_ULONG; 
typedef void CK_POINTER                CK_VOID_PTR; 
typedef CK_BYTE                        CK_CHAR;
typedef CK_ULONG                       CK_FLAGS; 
typedef CK_ULONG                       CK_SLOT_ID; 
typedef CK_BYTE CK_POINTER             CK_BYTE_PTR; 
typedef CK_USHORT CK_POINTER           CK_USHORT_PTR; 
typedef CK_ULONG CK_POINTER            CK_ULONG_PTR; 
typedef CK_ULONG                       CK_SESSION_HANDLE; 
typedef CK_SESSION_HANDLE CK_POINTER   CK_SESSION_HANDLE_PTR; 
typedef CK_ULONG                       CK_OBJECT_HANDLE; 
typedef CK_OBJECT_HANDLE CK_POINTER    CK_OBJECT_HANDLE_PTR;
typedef CK_USHORT                      CK_OBJECT_CLASS;
typedef CK_USHORT                      CK_MECHANISM_TYPE; 
typedef CK_MECHANISM_TYPE CK_POINTER   CK_MECHANISM_TYPE_PTR;
typedef CK_USHORT                      CK_USER_TYPE;
typedef CK_CHAR CK_POINTER             CK_CHAR_PTR;
typedef CK_SLOT_ID CK_POINTER          CK_SLOT_ID_PTR;
typedef CK_USHORT                      CK_STATE;
typedef CK_USHORT                      CK_ATTRIBUTE_TYPE;
typedef CK_USHORT                      CK_KEY_TYPE;

typedef struct CK_SESSION_INFO
	{
	CK_SLOT_ID slotID;
	CK_STATE state;
	CK_FLAGS flags;
	CK_ULONG ulDeviceError;
	}
CK_SESSION_INFO;

typedef CK_SESSION_INFO CK_POINTER CK_SESSION_INFO_PTR;

typedef struct CK_MECHANISM
	{ 
	CK_MECHANISM_TYPE mechanism; 
	CK_VOID_PTR pParameter; 
	CK_ULONG ulParameterLen; 
	}
CK_MECHANISM; 

typedef CK_MECHANISM CK_POINTER        CK_MECHANISM_PTR; 
typedef CK_USHORT                      CK_RV; 

typedef struct CK_ATTRIBUTE
	{
	CK_ATTRIBUTE_TYPE type;
	CK_VOID_PTR pValue;
	CK_ULONG ulValueLen;
	}
CK_ATTRIBUTE;

typedef struct RSA_KEY_PAIR_TEMPLATE
	{
	CK_ATTRIBUTE *rsa_pub;
	CK_USHORT    rsa_pub_size; 
	CK_ATTRIBUTE *rsa_priv;
	CK_USHORT    rsa_priv_size;
	}
RSA_KEY_PAIR_TEMPLATE;

typedef CK_ATTRIBUTE CK_POINTER CK_ATTRIBUTE_PTR;

/* Misc */
typedef struct CK_VERSION
    {
    CK_BYTE major;
    CK_BYTE minor;
    }
    CK_VERSION;

typedef CK_VERSION CK_POINTER CK_VERSION_PTR;

typedef struct CK_INFO
    {
    CK_VERSION cryptokiVersion;         /* Cryptoki interface ver */
    CK_CHAR manufacturerID[32];         /* blank padded */
    CK_FLAGS flags;                     /* must be zero */
    CK_CHAR libraryDescription[32];     /* blank padded */
    CK_VERSION libraryVersion;          /* version of library */
    }
    CK_INFO;

typedef CK_INFO CK_POINTER CK_INFO_PTR;

typedef struct CK_SLOT_INFO
    {
    CK_CHAR slotDescription[64];
    CK_CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    }
    CK_SLOT_INFO;

typedef CK_SLOT_INFO CK_POINTER CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO
    {
    CK_CHAR label[32];
    CK_CHAR manufacturerID[32];
    CK_CHAR model[16];
    CK_BYTE serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;        /* max count */
    CK_ULONG ulSessionCount;           /* current count */
    CK_ULONG ulMaxRwSessionCount;      /* max count */
    CK_ULONG ulRwSessionCount;         /* current count */
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_CHAR utcTime[16];
    }
    CK_TOKEN_INFO;

typedef CK_TOKEN_INFO CK_POINTER CK_TOKEN_INFO_PTR;

typedef struct CK_MECHANISM_INFO
    {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
    }
    CK_MECHANISM_INFO;

typedef CK_MECHANISM_INFO CK_POINTER CK_MECHANISM_INFO_PTR;

typedef CK_USHORT CK_NOTIFICATION;

typedef CK_RV (* CK_NOTIFY)(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_NOTIFICATION   event,
  CK_VOID_PTR       pApplication  /* passed to C_OpenSession */
);

typedef struct CK_FUNCTION_LIST  CK_FUNCTION_LIST;

typedef CK_FUNCTION_LIST CK_PTR  CK_FUNCTION_LIST_PTR;

typedef CK_FUNCTION_LIST_PTR CK_PTR   CK_FUNCTION_LIST_PTR_PTR;


/* Function types */
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Initialize)(CK_VOID_PTR pReserved);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Terminate)(void);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetInfo)(CK_INFO_PTR pInfo);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_USHORT_PTR pusCount);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_USHORT_PTR pusCount);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_InitToken)(CK_SLOT_ID slotID, CK_CHAR_PTR pPin, CK_USHORT usPinLen, CK_CHAR_PTR pLabel);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_InitPIN)(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_USHORT usPinLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SetPIN)(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin, CK_USHORT usOldLen, CK_CHAR_PTR pNewPin, CK_USHORT usNewLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_CloseAllSessions)(CK_SLOT_ID slotID);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_USHORT usPinLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Logout)(CK_SESSION_HANDLE hSession);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usCount, CK_OBJECT_HANDLE_PTR phObject);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usCount, CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_USHORT_PTR pusSize);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usCount);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usCount);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usCount);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_USHORT usMaxObjectCount, CK_USHORT_PTR pusObjectCount);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_USHORT usDataLen, CK_BYTE_PTR pEncryptedData, CK_USHORT_PTR pusEncryptedDataLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_USHORT usPartLen, CK_BYTE_PTR pEncryptedPart, CK_USHORT_PTR pusEncryptedPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_USHORT_PTR pusLastEncryptedPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_USHORT usEncryptedDataLen, CK_BYTE_PTR pData, CK_USHORT_PTR pusDataLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_USHORT usEncryptedPartLen, CK_BYTE_PTR pPart, CK_USHORT_PTR pusPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_USHORT_PTR pusLastPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_USHORT usDataLen, CK_BYTE_PTR pDigest, CK_USHORT_PTR pusDigestLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_USHORT usPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_USHORT_PTR pusDigestLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_USHORT usDataLen, CK_BYTE_PTR pSignature, CK_USHORT_PTR pusSignatureLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_USHORT usPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_USHORT_PTR pusSignatureLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_USHORT usDataLen, CK_BYTE_PTR pSignature, CK_USHORT_PTR pusSignatureLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_USHORT usDataLen, CK_BYTE_PTR pSignature, CK_USHORT usSignatureLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_USHORT usPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_USHORT usSignatureLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_USHORT usSignatureLen, CK_BYTE_PTR pData, CK_USHORT_PTR pusDataLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_USHORT usPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_USHORT usPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPrivateKey, CK_OBJECT_HANDLE_PTR phPublicKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_USHORT_PTR pusWrappedKeyLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_USHORT usWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_USHORT usAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_USHORT usSeedLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_USHORT usRandomLen);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_CancelFunction)(CK_SESSION_HANDLE hSession);
typedef CK_RV CK_ENTRY (CK_PTR CK_C_PerformSelfTest)(CK_SLOT_ID slotId, CK_ULONG typeOfTest, CK_BYTE_PTR outputData, CK_ULONG sizeOfOutputData, CK_BYTE_PTR inputData, CK_ULONG_PTR sizeOfInputData);
typedef CK_RV CK_ENTRY (CK_PTR CK_Notify)(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication);

struct CK_FUNCTION_LIST
    {
    CK_VERSION version;
    CK_C_Initialize C_Initialize;
    CK_C_Finalize C_Finalize;
    CK_C_GetInfo C_GetInfo;
    CK_C_GetFunctionList C_GetFunctionList;
    CK_C_GetSlotList C_GetSlotList;
    CK_C_GetSlotInfo C_GetSlotInfo;
    CK_C_GetTokenInfo C_GetTokenInfo;
    CK_C_GetMechanismList C_GetMechanismList;
    CK_C_GetMechanismInfo C_GetMechanismInfo;
    CK_C_InitToken C_InitToken;
    CK_C_InitPIN C_InitPIN;
    CK_C_SetPIN C_SetPIN;
    CK_C_OpenSession C_OpenSession;
    CK_C_CloseSession C_CloseSession;
    CK_C_CloseAllSessions C_CloseAllSessions;
    CK_C_GetSessionInfo C_GetSessionInfo;
    CK_C_GetOperationState C_GetOperationState;
    CK_C_SetOperationState C_SetOperationState;
    CK_C_Login C_Login;
    CK_C_Logout C_Logout;
    CK_C_CreateObject C_CreateObject;
    CK_C_CopyObject C_CopyObject;
    CK_C_DestroyObject C_DestroyObject;
    CK_C_GetObjectSize C_GetObjectSize;
    CK_C_GetAttributeValue C_GetAttributeValue;
    CK_C_SetAttributeValue C_SetAttributeValue;
    CK_C_FindObjectsInit C_FindObjectsInit;
    CK_C_FindObjects C_FindObjects;
    CK_C_FindObjectsFinal C_FindObjectsFinal;
    CK_C_EncryptInit C_EncryptInit;
    CK_C_Encrypt C_Encrypt;
    CK_C_EncryptUpdate C_EncryptUpdate;
    CK_C_EncryptFinal C_EncryptFinal;
    CK_C_DecryptInit C_DecryptInit;
    CK_C_Decrypt C_Decrypt;
    CK_C_DecryptUpdate C_DecryptUpdate;
    CK_C_DecryptFinal C_DecryptFinal;
    CK_C_DigestInit C_DigestInit;
    CK_C_Digest C_Digest;
    CK_C_DigestUpdate C_DigestUpdate;
    CK_C_DigestKey C_DigestKey;
    CK_C_DigestFinal C_DigestFinal;
    CK_C_SignInit C_SignInit;
    CK_C_Sign C_Sign;
    CK_C_SignUpdate C_SignUpdate;
    CK_C_SignFinal C_SignFinal;
    CK_C_SignRecoverInit C_SignRecoverInit;
    CK_C_SignRecover C_SignRecover;
    CK_C_VerifyInit C_VerifyInit;
    CK_C_Verify C_Verify;
    CK_C_VerifyUpdate C_VerifyUpdate;
    CK_C_VerifyFinal C_VerifyFinal;
    CK_C_VerifyRecoverInit C_VerifyRecoverInit;
    CK_C_VerifyRecover C_VerifyRecover;
    CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
    CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
    CK_C_SignEncryptUpdate C_SignEncryptUpdate;
    CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
    CK_C_GenerateKey C_GenerateKey;
    CK_C_GenerateKeyPair C_GenerateKeyPair;
    CK_C_WrapKey C_WrapKey;
    CK_C_UnwrapKey C_UnwrapKey;
    CK_C_DeriveKey C_DeriveKey;
    CK_C_SeedRandom C_SeedRandom;
    CK_C_GenerateRandom C_GenerateRandom;
    CK_C_GetFunctionStatus C_GetFunctionStatus;
    CK_C_CancelFunction C_CancelFunction;
    CK_C_WaitForSlotEvent C_WaitForSlotEvent;
    };
    
/* C_ Extensions */
typedef CK_RV CK_ENTRY (CK_PTR CK_CA_SetApplicationID)(CK_ULONG, CK_ULONG);
typedef CK_RV CK_ENTRY (CK_PTR CK_CA_OpenApplicationID)(CK_SLOT_ID slotID, CK_ULONG ulHigh, CK_ULONG ulLow);
typedef CK_RV CK_ENTRY (CK_PTR CK_CA_CloseApplicationID)(CK_SLOT_ID slotID, CK_ULONG ulHigh, CK_ULONG ulLow);
  
/* Engine Extensions */  
typedef struct app_id_pair  
	{  
	CK_ULONG hi;  
	CK_ULONG low;  
	}  
app_id_pair;  
  
typedef struct session_desc  
	{  
	app_id_pair app_id;  
	CK_SESSION_HANDLE handle;  
	CK_SLOT_ID slot;  
	}  
session_desc;  

/*****************************************************************************/

/* P11 data structures are packed on Windows platform only. */
#if defined(WIN32) || defined(_WIN32)
#pragma pack(pop, e_lunaca3_h)
#endif

/*****************************************************************************/

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
}
#endif

#endif /* header_e_lunaca3_h */


