/* $Source: ossl_vob/sautil/sautil.c $ $Revision: 1.2 $ */
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

/*
 * Coding conventions:
 *
 * 1. Code adapted from SafeNet's engine "e_lunaca3.c" uses OpenSSL indentation.
 *    Only legacy code uses two spaces for indentation.
 *
 * 2. Write C-language source only; i.e., no C++ comments.
 *
 * 3. Support C or C++ compiler in the field; i.e., 
 *
 *    #ifdef __cplusplus
 *    extern "C" {
 *    #endif
 *    <code not including headers>
 *    #ifdef __cplusplus
 *    }
 *    #endif
 *
 */

/* AIX: _POSIX_SOURCE, _XOPEN_SOURCE_EXTENDED, SAUTIL_HAVE_NO_OPTARG */
#if defined( OS_AIX ) || defined( AIX ) || defined ( _AIX )
#define _POSIX_SOURCE  (1)
#define _XOPEN_SOURCE_EXTENDED  (1)
#define SAUTIL_HAVE_NO_OPTARG  (1)
#endif /* AIX */

/* SAUTIL_HAVE_OPTARG */
#ifdef OS_WIN32
#undef SAUTIL_HAVE_OPTARG
#else
#ifndef SAUTIL_HAVE_NO_OPTARG
#define SAUTIL_HAVE_OPTARG  (1)
#endif
#endif

/* NOTE: if OS_WIN32 defined then Windows platform; otherwise, UNIX platform */

/* headers (system) */
#ifdef OS_WIN32
#include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#ifdef OS_WIN32
  #include <conio.h>
  #include <sys/types.h>
  #include <sys/stat.h>
  #define LOCAL_SLEEP(__sec)  Sleep(__sec)
#else /* OS_WIN32 */
  #include <fcntl.h>
  #include <termios.h>
  #include <unistd.h>
  #include <dlfcn.h>
  #include <sys/types.h>
  #include <sys/stat.h>
  #define LOCAL_SLEEP(__sec)  sleep(__sec)
#endif /* OS_WIN32 */

/* headers (openssl) */
#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/dso.h>

#ifndef OPENSSL_NO_RSA  
#include <openssl/rsa.h>  
#endif /* OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA  
#include <openssl/dsa.h>  
#endif /* OPENSSL_NO_DSA */

/* detect ecdsa (minimum version is 0.9.8l) */
#if (1) && (OPENSSL_VERSION_NUMBER >= 0x009080cfL) && !defined(OPENSSL_NO_ECDSA) && !defined(OPENSSL_NO_EC)
#define LUNA_OSSL_ECDSA  (1) 
#endif /* OPENSSL_NO_ECDSA... */

#if defined(LUNA_OSSL_ECDSA)
/* NOTE: "ec_lcl.h" is not bundled with 0.9.8l */
/* NOTE: "ecs_locl.h" is not bundled with 0.9.8l */
#include <openssl/ec_lcl.h>
#include <openssl/ecs_locl.h>
#include <openssl/ec.h>  
#include <openssl/ecdsa.h>  
#endif /* LUNA_OSSL_ECDSA */

/* headers (luna) */
#include  "e_lunaca3.h"
#include  "sautil.h"

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************/

#define LOCAL_APP_NAME  "sautil"
#define LOCAL_APP_VERSION  "v2.0.0-2"

/* SAUTIL_HAVE_OPTARG */
#ifndef SAUTIL_HAVE_OPTARG
static int getopt(int argc, char * const argv[], const char *optstring);
static char *optarg = 0;
#endif

/* Local defs */
#undef CA3UTIL_DIFFIE_HELLMAN /* NOTE: defunct */
#define CA3UTIL_MAX_STRING  (256)

/* Macros */
#define LUNA_DIM(a__)  (sizeof(a__) / sizeof((a__)[0]))
#define LUNA_MIN(a__, b__)  ( ((a__) < (b__)) ? (a__) : (b__) )
#define LUNA_DIFF(a__, b__)  ( ((a__) < (b__)) ? ((b__) - (a__)) : ((a__) - (b__)) )

/* Macros */
#define LUNACA3err(_foonum1, _foonum2)  do {} while (0)
#define ERR_add_error_data(_foonum1, _foosz1)  do { fprintf(stderr, "%s failed. \n", (char*)_foosz1); } while (0)

/* Definitions for managing session contexts */
typedef struct
	{
	int flagInit;  /* flag; true if valid */
	CK_SESSION_HANDLE hSession; /* the session handle */
	} 
luna_context_t;

#define LUNA_CONTEXT_T_INIT  { 0, 0 }

/* Forward references */
static int 
luna_restore_keyfile(CK_SLOT_ID slotid, CK_OBJECT_HANDLE pub_handle, char *keypair_fname, char *szkeytype);

int 
loggedin( CK_SLOT_ID slotid );

static int 
luna_select_key(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE* hout, char *szkeytype);

static void
sautil_sprint_unique(char *szPubLabel, char *szPrivLabel, 
  const char *szKeytype, unsigned uKeysize);

static CK_RV
sautil_sha1_prng(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR baSha1);

#if defined(LUNA_OSSL_ECDSA)
static int
op_generate_ecdsa_key_pair(CK_SLOT_ID slotid, CK_USHORT modulussize, 
  char *keypair_fname, char *param_fname);

static int
write_pem_ecdsa_key_pair(CK_SESSION_HANDLE session_handle, 
  CK_OBJECT_HANDLE pub_handle, 
  CK_OBJECT_HANDLE priv_handle, 
  char *keypair_fname);

static CK_OBJECT_HANDLE
luna_find_ecdsa_handle(luna_context_t *ctx, EC_KEY *dsa, int flagPrivate);

static int
op_delete_ecdsa_key_pair(CK_SLOT_ID slotid, char *keypair_fname);
#endif /* LUNA_OSSL_ECDSA */

static CK_RV
luna_get_attribute(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle, CK_ATTRIBUTE_PTR a_template);

static CK_RV sautil_ckatab_malloc_object(
  CK_ATTRIBUTE *tab, CK_ULONG tabsize,
  CK_OBJECT_HANDLE hObject,
  CK_SESSION_HANDLE hSession);

static void sautil_ckatab_free_all(CK_ATTRIBUTE *tab, CK_ULONG tabsize);

static void luna_dump_hex(FILE* fp, const char* szContext, unsigned char* id, unsigned size);

static void sautil_ckatab_malloc_replace(CK_ATTRIBUTE *tab, CK_ULONG tabsize,
  CK_ATTRIBUTE_TYPE type,
  CK_BYTE_PTR pValue, /* can be null */
  CK_ULONG ulValueLen);


/* Library entry points */
static DSO *luna_dso = NULL;

static struct
	{
	CK_C_GetFunctionList C_GetFunctionList;
	CK_FUNCTION_LIST_PTR std;
	struct ext_s
		{
		CK_CA_SetApplicationID CA_SetApplicationID;
		CK_CA_OpenApplicationID CA_OpenApplicationID;
		CK_CA_CloseApplicationID CA_CloseApplicationID;
		}
	ext;
	}
	p11 = { 0, 0 };

static CK_RV sautil_init(void);
static void sautil_fini(void);
static void sautil_exit(int errcode);
static int sautil_gets_password(char *secretString, unsigned maxlen);

/* misc */
static int want_help = 0;
static int verbose = 0;
static CK_ULONG app_id_hi = 0;
static CK_ULONG app_id_lo = 0;
static CK_SLOT_ID slot_id = 0;
static unsigned operation = 0;
static CK_USHORT  modulus_size = 0;
static char *key_filename = NULL;
static char *key_keytype = NULL;
static char *key_paramfile = NULL;
static char sautil_password[255+1];
static char sautil_szcurve[255+1];

/* RSA public exponent */
static enum enum_opt_sel_exponent {
  OPT_SEL_EXPNULL,
  OPT_SEL_EXP3, /* 0x3 */
  OPT_SEL_EXP4, /* 0x10001 (default) */
  OPT_SEL_EXPOTHER /* user-defined */
}
optSelExponent = OPT_SEL_EXP4;
 
static unsigned char* bpOptSelExponent = NULL; 
static unsigned countofOptSelExponent = 0; 
  
static unsigned char* parse_hex_bytes(const char* inptr, int separator, unsigned *outsize); 
 
static int key_handle = 0;


#if defined(LUNA_OSSL_ECDSA)

/* ECDSA curves */

#define SAUTIL_EC_CURVE_MAX_BYTES  (16)
#define SAUTIL_EC_CURVE_MIN_BYTES  (7)
#define SAUTIL_EC_CURVE_MIN_STRLEN  (9)

typedef struct sautil_curve_s
{
  CK_BYTE pValue[SAUTIL_EC_CURVE_MAX_BYTES];
  CK_ULONG ulValueLen;
  const char *name; /* name must start with "OID_" */
}  sautil_curve_t;

static sautil_curve_t sautil_curves[] = {
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x06},7,"OID_secp112r1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x07},7,"OID_secp112r2"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x1C},7,"OID_secp128r1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x1D},7,"OID_secp128r2"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x09},7,"OID_secp160k1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x08},7,"OID_secp160r1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x1E},7,"OID_secp160r2"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x1F},7,"OID_secp192k1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x20},7,"OID_secp224k1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x21},7,"OID_secp224r1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x0A},7,"OID_secp256k1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x22},7,"OID_secp384r1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x23},7,"OID_secp521r1"},

{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x01},10,"OID_X9_62_prime192v1"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x02},10,"OID_X9_62_prime192v2"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x03},10,"OID_X9_62_prime192v3"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x04},10,"OID_X9_62_prime239v1"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x05},10,"OID_X9_62_prime239v2"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x06},10,"OID_X9_62_prime239v3"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07},10,"OID_X9_62_prime256v1"},

{{0x06,0x05,0x2B,0x81,0x04,0x00,0x04},7,"OID_sect113r1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x05},7,"OID_sect113r2"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x16},7,"OID_sect131r1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x17},7,"OID_sect131r2"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x01},7,"OID_sect163k1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x02},7,"OID_sect163r1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x0F},7,"OID_sect163r2"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x18},7,"OID_sect193r1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x19},7,"OID_sect193r2"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x1A},7,"OID_sect233k1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x1B},7,"OID_sect233r1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x03},7,"OID_sect239k1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x10},7,"OID_sect283k1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x11},7,"OID_sect283r1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x24},7,"OID_sect409k1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x25},7,"OID_sect409r1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x26},7,"OID_sect571k1"},
{{0x06,0x05,0x2B,0x81,0x04,0x00,0x27},7,"OID_sect571r1"},

{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x01},10,"OID_X9_62_c2pnb163v1"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x02},10,"OID_X9_62_c2pnb163v2"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x03},10,"OID_X9_62_c2pnb163v3"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x04},10,"OID_X9_62_c2pnb176v1"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x05},10,"OID_X9_62_c2tnb191v1"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x06},10,"OID_X9_62_c2tnb191v2"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x07},10,"OID_X9_62_c2tnb191v3"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x0A},10,"OID_X9_62_c2pnb208w1"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x0B},10,"OID_X9_62_c2tnb239v1"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x0C},10,"OID_X9_62_c2tnb239v2"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x0D},10,"OID_X9_62_c2tnb239v3"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x10},10,"OID_X9_62_c2pnb272w1"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x11},10,"OID_X9_62_c2pnb304w1"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x12},10,"OID_X9_62_c2tnb359v1"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x13},10,"OID_X9_62_c2pnb368w1"},
{{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x00,0x14},10,"OID_X9_62_c2tnb431r1"},

#if 0
/* FIXME: d2i_ECParameters fails so we cannot support these curves yet. */
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x01},11,"OID_brainpoolP160r1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x02},11,"OID_brainpoolP160t1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x03},11,"OID_brainpoolP192r1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x04},11,"OID_brainpoolP192t1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x05},11,"OID_brainpoolP224r1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x06},11,"OID_brainpoolP224t1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07},11,"OID_brainpoolP256r1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x08},11,"OID_brainpoolP256t1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x09},11,"OID_brainpoolP320r1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0a},11,"OID_brainpoolP320t1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0b},11,"OID_brainpoolP384r1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0c},11,"OID_brainpoolP384t1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0d},11,"OID_brainpoolP512r1"},
{{0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0e},11,"OID_brainpoolP512t1"},
#endif
};

#endif /* LUNA_OSSL_ECDSA */


static void
display_help_and_exit(void)
{
  fprintf(stdout, LOCAL_APP_NAME" "LOCAL_APP_VERSION" " __DATE__ " " __TIME__ " \n"
                  "  Copyright (C) 2009 SafeNet, Inc. All rights reserved. \n\n"
                  "  Options:\n"
		  "    -o         open application connection.\n"
		  "    -c         close application connection.\n"
 	 	  "    -i hi:lo   application id high and low component. 32-bit values.\n"
		  "    -s slot    token slot number.\n"
		  "    -p pswd    plaintext password (please use -q instead).\n" 
		  "    -q         prompt for password (instead of -p).\n" 
		  "    -v         verbose.\n"
		  "    -h         show help message in full.\n"
		  "    -g size    generate RSA key pair with size = {512,1024,2048,4096} bits.\n"
		  "    -g 0       delete RSA keypair from HSM (used with -f file option).\n"
		  "    -d size[:paramfile]    generate DSA key pair with size = {1024} bits.\n"
		  "    -d 0       delete DSA keypair from HSM (used with -f file option).\n"
#if defined(LUNA_OSSL_ECDSA)
		  "    -m curve   generate ECDSA key pair with curve name.\n"
		  "    -m 0       delete ECDSA keypair from HSM (used with -f file option).\n"
		  "    -n         print a list of supported curve names.\n"
#endif /* LUNA_OSSL_ECDSA */
#ifdef CA3UTIL_DIFFIE_HELLMAN
		  "    -e size    generate a DH key pair.\n"
#endif /* CA3UTIL_DIFFIE_HELLMAN */
		  "    -f file    specify name of keyfile.\n"
		  "    -3         public exponent is 0x3 for RSA key generation.\n"
		  "    -4         public exponent is 0x10001 for RSA key generation (default).\n"
		  "    -x bytes   public exponent is a colon-separated list of\n"
		  "               hex bytes for RSA key generation; e.g., 03 ; e.g., 01:00:01 .\n"
		  "    -a 0[:keytype]  write keyfile for existing keytype = {RSA,DSA,ECDSA}.\n\n"
		  "  EXAMPLE 1: open persistent application connection and login: \n"
		  "    # sautil -v -s 1 -i 10:11 -o -q \n\n"
		  "  EXAMPLE 2: close persistent application connection: \n"
		  "    # sautil -v -s 1 -i 10:11 -c \n\n"
		  "    NOTE: remember to close persistent connection when HSM not in use. \n\n"
		  "  EXAMPLE 3: generate a new RSA keypair and write the keyfile: \n"
		  "    # sautil -v -s 1 -i 10:11 -g 2048 -f tmpkey.pem \n\n"
		  "  EXAMPLE 4: select an existing RSA key and write the keyfile: \n"
		  "    # sautil -v -s 1 -i 10:11 -a 0:RSA -f tmpkey.pem \n\n"
		  "  EXAMPLE 5: connect, write keyfile, and disconnect in a single command-line: \n"
		  "    # sautil -v -s 1 -i 10:11 -a 0:RSA -f tmpkey.pem -o -q -c \n\n"
		  );

#if defined(LUNA_OSSL_ECDSA)
{
  CK_ULONG ii = 0;
  
  /* if help explicitly requested then display curves */
  if (want_help) {
    fprintf(stdout, "  Note (valid curve names used with -m option):\n");
    for (ii = 0; ii < LUNA_DIM(sautil_curves); ii++) {
      if ( (ii % 3) == 0) {
        fprintf(stdout, "\n ");
      }
      fprintf(stdout, "%25s ", (char*)sautil_curves[ii].name);
    }
    fprintf(stdout, "\n");
  }
}
#endif

  sautil_exit(-1);
}	    


/* dump a long string of support EC curves */
static void
display_oids_and_exit(void)
{
#if defined(LUNA_OSSL_ECDSA)
{
  CK_ULONG ii = 0;
  
  /* if help explicitly requested then display curves */
  if (1) {
    for (ii = 0; ii < LUNA_DIM(sautil_curves); ii++) {
      fprintf(stdout, "%s ", (char*)sautil_curves[ii].name);
    }
  }
}
  sautil_exit(0);
#else
  sautil_exit(-1);
#endif
}
  

static BIO *bio_err=NULL;

static void
print_errors_and_exit(void)
{
    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
	    BIO_set_fp(bio_err, stderr, BIO_NOCLOSE|BIO_FP_TEXT);
	    
    ERR_print_errors(bio_err);
    sautil_exit(-1);
}


int
parse_args(int argc, char *argv[])
{
  char app_id_buf[128];
  char *p = NULL; 
  int option = 0;
  
  memset(app_id_buf, 0, sizeof(app_id_buf));
   
  if (argc > 1) {
    while ((option = getopt(argc, argv, "nq34hex:d:g:cos:i:vf:p:a:R:m:")) != EOF) {
      switch ((char) option) {
	case 'g': 
	  if (optarg == NULL) display_help_and_exit();
	  if (!isdigit(optarg[0])) {
	    fprintf(stderr, "Must specify a valid modulus size. [%s] is not\n", optarg);
	    return -1;
	  }
	  
	  modulus_size =  atoi(optarg);

          if (!modulus_size) {
	    operation |= OP_DELETE_RSA_KEY_PAIR;
	    break;
	  }
	  operation |= OP_GENERATE_RSA_KEY_PAIR;
	  if (modulus_size < 1024) {
	      fprintf(stderr, "Invalid modulus size %u less than 1024. \n", (unsigned)modulus_size);
	      return -1;
	  }
	  if (modulus_size % 256) {
	      fprintf(stderr, "Invalid modulus size %u modulo 256. \n", (unsigned)modulus_size);
	      return -1;
	  }
	  break;
	case 'd':
	  if (optarg == NULL) display_help_and_exit();
	  if (!isdigit(optarg[0])) {
	    fprintf(stderr, "Must specify a valid modulus size. [%s] is not\n", optarg);
	    return -1;
	  }
	  modulus_size =  atoi(optarg);
	  if (!modulus_size) {
	    operation |= OP_DELETE_DSA_KEY_PAIR;
	    break;
	  }
	  operation |= OP_GENERATE_DSA_KEY_PAIR;
	  key_paramfile = NULL; /* default */
	  switch (modulus_size) {
	    case 1024:
	      if ( (p = strchr(optarg, ':')) != NULL ) {
	        key_paramfile = strdup(p+1);
	      }
	      break;
	    default:
	      fprintf(stderr, "Invalid DSA key size. Only 1024-bit supported at this time.\n");
	      return -1;
	  }
	  break;
#if defined(LUNA_OSSL_ECDSA)
	case 'm':
	  if (optarg == NULL) {
            fprintf(stderr, "Missing argument for option -m.\n");
	    display_help_and_exit();
	  }
	  key_paramfile = NULL; /* default */
	  if (strcmp(optarg, "0") == 0) {
	    operation |= OP_DELETE_ECDSA_KEY_PAIR;
	    modulus_size = 0;
	  } else if (strncmp(optarg, "OID_", 4) == 0) {
	    operation |= OP_GENERATE_ECDSA_KEY_PAIR;
	    modulus_size = 1024;
	    if ( (p = strchr(optarg, ':')) != NULL ) {
	      key_paramfile = strdup(p+1);
	    } else {
	      strncpy(sautil_szcurve, optarg, (sizeof(sautil_szcurve)-1)); sautil_szcurve[sizeof(sautil_szcurve)-1] = 0;
	    }
	  } else {
            fprintf(stderr, "Invalid argument for option -m.\n");
            display_help_and_exit();
	  }
	  break;
	case 'n':
	  display_oids_and_exit();
	  break;
#endif /* LUNA_OSSL_ECDSA */
#ifdef CA3UTIL_DIFFIE_HELLMAN
        case 'e':
          if (optarg == NULL) display_help_and_exit();
	  modulus_size =  atoi(optarg);
	  operation |= OP_GENERATE_DH_KEY_PAIR;
	  switch (modulus_size) {
	    case 1024:
	      break;
	    default:
	      fprintf(stderr, "Invalid DH key size.\n");
	      return -1;
	  }
	  break;
#endif /* CA3UTIL_DIFFIE_HELLMAN */
	case 'o':
	  operation |= OP_OPEN;
	  break;
	case 'c':
	  operation |= OP_CLOSE;
	  break;
        case 's':
          if (optarg == NULL) display_help_and_exit();
	  slot_id = atoi(optarg);
	  break;
	case 'a':
	case 'R':
	  if (optarg == NULL) display_help_and_exit();
	  operation |= OP_RESTORE_KEYFILE;
	  if (!isdigit(optarg[0])) {
	     fprintf(stderr, "Must specify a numeric key handle (or zero)\n");
	     return -1;
	  }
	  if ( (p = strchr(optarg, ':')) != NULL ) {
	    key_keytype = strdup(p+1);
	  } else {
	    key_keytype = strdup("RSA"); /* default */
	  }
	  key_handle = atoi(optarg);
	  if (!key_handle) {
	     /* interactive mode */
	  }
	  break;
	case '3':
	  optSelExponent = OPT_SEL_EXP3;
	  break;
	case '4':
	  optSelExponent = OPT_SEL_EXP4;
	  break;
	case 'x':
	  if (optarg == NULL) display_help_and_exit();
	  optSelExponent = OPT_SEL_EXPOTHER;
	  bpOptSelExponent = parse_hex_bytes(optarg, ':', &countofOptSelExponent);
	  if (bpOptSelExponent == NULL) {
	    fprintf(stderr, "Parse error for after \'-x\'.\n");
	    return -1;
	  }
	  break;
        case 'p':
          if (optarg == NULL) display_help_and_exit();
          strncpy(sautil_password, optarg, (sizeof(sautil_password)-1)); sautil_password[sizeof(sautil_password)-1] = 0;
          if (strlen(sautil_password) < 4) {
	    fprintf(stderr, "Failed to read password (or password too short).\n");
	    return -1;
          }
          break;
        case 'q': /* prompt for password (instead of -p) */
          fprintf(stdout, "Enter password for slot %u: \n", (unsigned)slot_id);
          if (sautil_gets_password(sautil_password, (sizeof(sautil_password)-1)) < 4) { 
	    fprintf(stderr, "Failed to read password (or password too short).\n");
	    return -1;
          }
          break;
	case 'f':
	  if (optarg == NULL) display_help_and_exit();
	  key_filename = strdup(optarg);
	  break;
	case 'i':
	  if (optarg == NULL) display_help_and_exit();
	  memset(app_id_buf, 0, 128);
	  strncpy(app_id_buf, optarg, 128);
	  p = strchr(app_id_buf, ':' );
	  if (!p) {
            fprintf(stderr, "Invalid App ID parameter [%s]. Must be ULONG:ULONG\n", app_id_buf);
	    return -1;
	  }
	  p[0] = 0;
	  p++;
	  app_id_hi = atoi(app_id_buf);
	  app_id_lo = atoi(p);
	  break;
	case 'v':
	  verbose = 1;
	  break;
	case 'h':
	  want_help = 1;
	  /* fall through */
        default:
	  display_help_and_exit();
	  break;
      }
    }
  } else
    display_help_and_exit();

  return 0;
  
}




int
init_dh_key_template(CK_ATTRIBUTE **pubTemp, CK_ATTRIBUTE **privTemp, 
		     CK_USHORT *pubTempSize, CK_USHORT *privTempSize,
		     CK_BYTE *pub_key_label, CK_BYTE *priv_key_label,
		     const CK_BYTE *dh_prime, const CK_USHORT dh_prime_size,
		     const CK_BYTE *dh_base,  const CK_USHORT dh_base_size
		     )
{
  CK_BBOOL bTrue = TRUE, bFalse = FALSE;
  CK_ATTRIBUTE *pubTemplate, *privTemplate;
  
  CK_ATTRIBUTE dh_pub_template[] =
  {
    { CKA_LABEL,    0, 0},
    { CKA_PRIVATE,  0, sizeof(CK_BBOOL) },
    { CKA_TOKEN,    0, sizeof(CK_BBOOL) },
    { CKA_PRIME,    0, 0},
    { CKA_BASE,     0, 0},
    { CKA_DERIVE,   0, sizeof(CK_BBOOL) },
  };

   
  
  CK_ATTRIBUTE dh_priv_template[] =
  {
    {CKA_LABEL,      0, 0},
    {CKA_TOKEN,      0, 1},
    {CKA_PRIVATE,    0, 1},
    {CKA_SENSITIVE,  0, 1},
    {CKA_DERIVE,     0, 1},
  };

  
  if (!pub_key_label || !priv_key_label) {
    fprintf(stderr, "key label fields need to be specified\n");
    return -1;
  }
 
 
  dh_priv_template[0].pValue         = priv_key_label;
  dh_priv_template[0].ulValueLen     = (CK_ULONG)strlen((char*)priv_key_label);
  dh_priv_template[1].pValue         = &bTrue;
  dh_priv_template[2].pValue         = &bTrue;
  dh_priv_template[3].pValue         = &bTrue;
  dh_priv_template[4].pValue         = &bTrue;
      
  dh_pub_template[0].pValue         = pub_key_label;
  dh_pub_template[0].ulValueLen     = (CK_ULONG)strlen((char*)pub_key_label);
  dh_pub_template[1].pValue         = &bFalse;
  dh_pub_template[2].pValue         = &bTrue;
  dh_pub_template[3].pValue         = (CK_BYTE *) dh_prime;
  dh_pub_template[3].ulValueLen     = dh_prime_size;
  dh_pub_template[4].pValue         = (CK_BYTE *) dh_base;
  dh_pub_template[4].ulValueLen     = dh_base_size;
  dh_pub_template[5].pValue         = &bTrue;
								  
   
  pubTemplate  =  (CK_ATTRIBUTE *) malloc(sizeof(dh_pub_template));
  privTemplate =  (CK_ATTRIBUTE *) malloc(sizeof(dh_priv_template));
  *pubTempSize  = sizeof(dh_pub_template)  / sizeof(CK_ATTRIBUTE);
  *privTempSize = sizeof(dh_priv_template) / sizeof(CK_ATTRIBUTE);

  memcpy(pubTemplate,  dh_pub_template,  sizeof(dh_pub_template));
  memcpy(privTemplate, dh_priv_template, sizeof(dh_priv_template));
 
  *pubTemp = pubTemplate;
  *privTemp = privTemplate;

  return 0;
}

int
init_dsa_key_template(CK_ATTRIBUTE **pubTemp, CK_ATTRIBUTE **privTemp, 
		      CK_USHORT *pubTempSize, CK_USHORT *privTempSize,
		      CK_BYTE *pub_key_label, CK_BYTE *priv_key_label,
		      const CK_BYTE *dsa_prime, const CK_USHORT dsa_prime_size,
		      const CK_BYTE *dsa_sub_prime, const CK_USHORT dsa_sub_prime_size,
		      const CK_BYTE *dsa_base, const CK_USHORT dsa_base_size,
		      CK_BYTE *dsa_id, CK_ULONG dsa_id_size
		     )
{
  CK_BBOOL bTrue = TRUE, bFalse = FALSE;
  CK_ATTRIBUTE *pubTemplate = NULL;
  CK_ATTRIBUTE *privTemplate = NULL;
  
  CK_ATTRIBUTE dsa_pub_template[] =
  {
    {CKA_LABEL,    0, 0},
    {CKA_TOKEN,    0, 0},
    {CKA_PRIME,    0, 0},
    {CKA_SUBPRIME, 0, 0},
    {CKA_BASE,     0, 0},
    {CKA_VERIFY,   0, 0},
    {CKA_ID,       0, 0},
  };

  CK_ATTRIBUTE dsa_priv_template[] =
  {
    {CKA_LABEL,     0, 0},
    {CKA_TOKEN,     0, 0},
    {CKA_PRIVATE,   0, 0},
    {CKA_SENSITIVE, 0, 0},
    {CKA_SIGN,      0, 0},
    {CKA_ID,        0, 0},
  };

  if (!pub_key_label || !priv_key_label) {
    fprintf(stderr, "key label fields need to be specified\n");
    return -1;
  }
 
  /* set attribute */  
  sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_LABEL, (CK_BYTE_PTR)pub_key_label, (CK_ULONG)strlen((char*)pub_key_label));
  sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_TOKEN, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_PRIME, (CK_BYTE_PTR)dsa_prime, dsa_prime_size);
  sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_SUBPRIME, (CK_BYTE_PTR)dsa_sub_prime, dsa_sub_prime_size);
  sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_BASE, (CK_BYTE_PTR)dsa_base, dsa_base_size);
  sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_VERIFY, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(dsa_pub_template, LUNA_DIM(dsa_pub_template), CKA_ID, dsa_id, dsa_id_size);
  
  sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_LABEL, (CK_BYTE_PTR)priv_key_label, (CK_ULONG)strlen((char*)priv_key_label));
  sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_TOKEN, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_PRIVATE, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_SENSITIVE, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_SIGN, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(dsa_priv_template, LUNA_DIM(dsa_priv_template), CKA_ID, dsa_id, dsa_id_size);
  
  pubTemplate = (CK_ATTRIBUTE *) malloc(sizeof(dsa_pub_template));
  privTemplate = (CK_ATTRIBUTE *) malloc(sizeof(dsa_priv_template));
  (*pubTempSize) = sizeof(dsa_pub_template)  / sizeof(CK_ATTRIBUTE);
  (*privTempSize) = sizeof(dsa_priv_template) / sizeof(CK_ATTRIBUTE);

  memcpy(pubTemplate, dsa_pub_template, sizeof(dsa_pub_template));
  memcpy(privTemplate, dsa_priv_template, sizeof(dsa_priv_template));
 
  (*pubTemp) = pubTemplate;
  (*privTemp) = privTemplate;

  return 0;
}



static int
init_rsa_key_template(CK_ATTRIBUTE **pubTemp, CK_ATTRIBUTE **privTemp, CK_USHORT *pubTempSize, CK_USHORT *privTempSize,
                  const CK_USHORT modulusBits, const CK_BYTE *publicExponent, const CK_USHORT publicExponentSize,
		  CK_BYTE *privKeyLabel, CK_BYTE *pubKeyLabel,
		  CK_BYTE *idSha1, CK_USHORT idSha1Len)
{
  CK_BBOOL bTrue = TRUE, bFalse = FALSE;
  CK_ATTRIBUTE *pubTemplate = NULL, *privTemplate = NULL;
  CK_ULONG ulModBits = modulusBits;

  CK_ATTRIBUTE rsa_pub_template[] = {
    {CKA_TOKEN,              0,   0},
    {CKA_ENCRYPT,            0,   0},
    {CKA_VERIFY,             0,   0},
    {CKA_MODULUS_BITS,       0,   0},
    {CKA_PUBLIC_EXPONENT,    0,   0},
    {CKA_LABEL,              0,   0},
    {CKA_ID,                 0,   0},
  };
  
  CK_ATTRIBUTE rsa_priv_template[] = {
    {CKA_LABEL,              0,   0},
    {CKA_TOKEN,              0,   0},
    {CKA_PRIVATE,            0,   0}, 
    {CKA_SENSITIVE,          0,   0},
    {CKA_DECRYPT,            0,   0},
    {CKA_SIGN,               0,   0},
    {CKA_ID,                 0,   0},
  };

  if (!privKeyLabel || !pubKeyLabel) {
    fprintf(stderr, "BUG: !privKeyLabel || !pubKeyLabel\n");
    return -1;
  }

  /* set attribute */  
  sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_TOKEN, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_ENCRYPT, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_VERIFY, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_MODULUS_BITS, (CK_BYTE_PTR)&ulModBits, sizeof(ulModBits));
  sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_PUBLIC_EXPONENT, (CK_BYTE_PTR)publicExponent, publicExponentSize);
  sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_LABEL, (CK_BYTE_PTR)pubKeyLabel, (CK_ULONG)strlen((char*)pubKeyLabel));
  sautil_ckatab_malloc_replace(rsa_pub_template, LUNA_DIM(rsa_pub_template), CKA_ID, idSha1, idSha1Len);

  sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_LABEL, (CK_BYTE_PTR)privKeyLabel, (CK_ULONG)strlen((char*)privKeyLabel));
  sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_TOKEN, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_PRIVATE, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_SENSITIVE, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_DECRYPT, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_SIGN, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(rsa_priv_template, LUNA_DIM(rsa_priv_template), CKA_ID, idSha1, idSha1Len);
 
  pubTemplate = (CK_ATTRIBUTE *) malloc(sizeof(rsa_pub_template));
  privTemplate = (CK_ATTRIBUTE *) malloc(sizeof(rsa_priv_template));
  memcpy(pubTemplate, rsa_pub_template, sizeof(rsa_pub_template));
  memcpy(privTemplate, rsa_priv_template, sizeof(rsa_priv_template));
  memset(rsa_pub_template, 0, sizeof(rsa_pub_template));
  memset(rsa_priv_template, 0, sizeof(rsa_priv_template));

  (*pubTemp) = pubTemplate;
  (*privTemp) = privTemplate;

  (*pubTempSize) = sizeof(rsa_pub_template) / sizeof(CK_ATTRIBUTE);
  (*privTempSize) = sizeof(rsa_priv_template) / sizeof(CK_ATTRIBUTE);
  
  return 0;
}

int
set_application_id(CK_ULONG appid_hi, CK_ULONG appid_lo)
{
  CK_RV ret;

  ret = p11.ext.CA_SetApplicationID(appid_hi, appid_lo);
  if (ret != CKR_OK) {
    fprintf(stderr, "CA_SetApplicationID: failed to set id. err 0x%x\n", (int) ret);
    return -1;
  } 

  if (verbose)
    fprintf(stdout, "Will use application ID [%lu:%lu].\n", appid_hi, appid_lo);

  return 0;
}

int
open_session(CK_SLOT_ID slotid, CK_SESSION_HANDLE *session_handle)
{
  CK_RV retCode;
  CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
  CK_SESSION_HANDLE shandle;

  retCode = p11.std->C_OpenSession(slotid, flags, (CK_BYTE_PTR)"Application", 0, &shandle);
  if(retCode !=CKR_OK) {
    fprintf(stderr, "Open Session Error: Slot number %d. err 0x%x\n", (int) slotid, (int) retCode);
    return -1;
  }

  if (verbose)
    fprintf(stdout, "Session opened. Handle %x \n", (int) shandle);

  (*session_handle) = shandle;
 
  return 0;
}

int
close_session(CK_SESSION_HANDLE session_handle)
{
  CK_RV retCode;

  retCode = p11.std->C_CloseSession(session_handle); session_handle = 0;
  if(retCode != CKR_OK) {
    fprintf(stderr, "Crystoki Close Session Error. Session handle %d  err 0x%x\n", (int) session_handle, (int) retCode);
    return -1;
  }

  return 0;
}


int
op_open_app_id(CK_SLOT_ID slotid, CK_ULONG appid_hi, CK_ULONG appid_lo)
{
  CK_SESSION_HANDLE session_handle;
  CK_RV retCode;
  int   ret = -1;
  
  ret = set_application_id(app_id_hi, app_id_lo);
  if (ret != 0)
    return -1;

  retCode = p11.ext.CA_OpenApplicationID(slotid, appid_hi, appid_lo);
  if (retCode != CKR_OK) {
    fprintf(stderr, "CA_OpenApplicationID: failed to open application id. err 0x%x\n", (int) retCode);
    fprintf(stderr, "                      invalid slot id or app id already open?\n");
    return -1;
  }
 
  if (verbose)
    fprintf(stdout, "Application ID [%lu:%lu] opened.\n", appid_hi, appid_lo);

  fprintf(stderr, "Open ok. \n");
     
  if (open_session(slotid, &session_handle) != 0)
    return -1;

#if 0
  fprintf(stdout, "C_Login: PED operation required\n");
#endif


  retCode = p11.std->C_Login(session_handle, CKU_USER, (CK_BYTE_PTR)sautil_password, (CK_ULONG)strlen((char*)sautil_password));
  if(retCode != CKR_OK) { 
    fprintf(stderr, "Crystoki Login Error: %04x slotid %d \n", (unsigned) retCode, (unsigned)slotid);
    goto err;
  }

#if 0
#define KM_TPV_M_OF_N_ACTIVATION                   0x04000000

  retCode = p11.ext.CA_GetExtendedTPV(slotid, &tpv, &tpvExt);
  if(retCode != CKR_OK) {    
    fprintf(stderr, "Crystoki CA_GetExtendedTPV Error: %04x slotid %d \n", (int) retCode, slotid);
    goto err;
  } 
    
  if (tpv & KM_TPV_M_OF_N_ACTIVATION) {
    if (verbose) 
      fprintf(stdout, "MofN activation required.\n");
    
    retCode = p11.ext.CA_ActivateMofN(session_handle, NULL_PTR, 0);
    if (retCode != CKR_OK) {  
      fprintf(stderr, "M of N activation failed.\n");
      fprintf(stderr, "Crystoki CA_ActivateMofN Error: %04x slotid %d \n", (int) retCode, slotid);
      goto err;
    }
  
  }
#endif
  
  fprintf(stdout, "\n\n");
  fprintf(stdout, "WARNING: Application Id %u:%u has been opened for access. Thus access will\n", (unsigned)appid_hi, (unsigned)appid_lo);
  fprintf(stdout, "         remain open until all sessions associated with this Application Id are\n");
  fprintf(stdout, "         closed or until the access is explicitly closed.\n\n"); 

  ret = 0;

err:
  
  if (close_session(session_handle) != 0) {
    session_handle = 0;
    return -1;
  }

  session_handle = 0;
  return ret;
}


int
op_close_app_id(CK_SLOT_ID slotid, CK_ULONG appid_hi, CK_ULONG appid_lo)
{
  CK_RV ret;

  ret = p11.ext.CA_CloseApplicationID(slotid, appid_hi, appid_lo);
  if (ret != CKR_OK) {
    fprintf(stderr, "CA_CloseApplicationID: failed to close application id. err 0x%x\n", (int) ret);
    return -1;
  } 

  fprintf(stderr, "Close ok. \n");
  return 0;
}


static int
write_pem_dsa_key_pair(CK_SESSION_HANDLE session_handle, 
		       CK_OBJECT_HANDLE pub_handle, CK_OBJECT_HANDLE priv_handle, 
		       char *keypair_fname)
{
  int ret = -1;
  CK_RV retCode = ~0;
  BIO *outfile = NULL;
  DSA *dsa = NULL;
  const unsigned ndxP = 0;
  const unsigned ndxQ = 1;
  const unsigned ndxG = 2;
  const unsigned ndxV = 3;
  CK_ATTRIBUTE ckaPublic[] = {
    { CKA_PRIME, NULL_PTR, 0 },
    { CKA_SUBPRIME, NULL_PTR, 0 },
    { CKA_BASE, NULL_PTR, 0 },
    { CKA_VALUE, NULL_PTR, 0 },
  };

  /* open file before hsm io */
  if ((outfile = BIO_new(BIO_s_file())) == NULL) {
    fprintf(stderr, "Cannot create BIO used to write out PEM key pair.\n");
    goto err;
  }

  if (BIO_write_filename(outfile, keypair_fname) <= 0) {
    fprintf(stderr, "Cannot open [%s] for writing.\n", keypair_fname);
    goto err;
  }

  /* extract public key */
  retCode = sautil_ckatab_malloc_object(
    ckaPublic, LUNA_DIM(ckaPublic),
    pub_handle,
    session_handle);
  if (retCode != CKR_OK) {
    fprintf(stderr, "Failed to extract DSA public key. err 0x%x\n", (int) retCode);
    goto err;
  }

  if (verbose) {
    luna_dump_hex(stdout, "CKA_VALUE=", ckaPublic[ndxV].pValue, ckaPublic[ndxV].ulValueLen);
  }

  /* get us an rsa structure and allocate its components */
  if ((dsa = DSA_new()) == NULL) goto err;
  if ((dsa->p = BN_new()) == NULL) goto err;
  if ((dsa->q = BN_new()) == NULL) goto err;
  if ((dsa->g = BN_new()) == NULL) goto err;
  if ((dsa->priv_key = BN_new()) == NULL) goto err;
  if ((dsa->pub_key  = BN_new()) == NULL) goto err;

  /* set private key to 1 or to keyhandle for possible optimization */
  if (!BN_one(dsa->priv_key)) goto err;
  if (priv_handle != 0) {
    if (!BN_set_word(dsa->priv_key, (unsigned long) priv_handle))  goto err;
  }

  /* Save public value and the rest */
  dsa->p = BN_bin2bn(ckaPublic[ndxP].pValue, ckaPublic[ndxP].ulValueLen, dsa->p);
  dsa->q = BN_bin2bn(ckaPublic[ndxQ].pValue, ckaPublic[ndxQ].ulValueLen, dsa->q);
  dsa->g = BN_bin2bn(ckaPublic[ndxG].pValue, ckaPublic[ndxG].ulValueLen, dsa->g);
  dsa->pub_key = BN_bin2bn(ckaPublic[ndxV].pValue, ckaPublic[ndxV].ulValueLen, dsa->pub_key);
  if (!PEM_write_bio_DSAPrivateKey(outfile, dsa, NULL, NULL, 0, NULL, NULL))
     goto err;
    
  ret = 0;
  
  if (verbose)
    fprintf(stdout, "Wrote file \"%s\".\n", (char*)keypair_fname);
  
err:
  sautil_ckatab_free_all(ckaPublic, LUNA_DIM(ckaPublic));
  return ret;
}


static void luna_dump_hex(FILE* fp, const char* szContext, unsigned char* id, unsigned size)
{
  unsigned ii = 0;
  fprintf(fp, "%s", (char*)szContext);
  for (ii = 0; ii < size; ii++) {
    fprintf(fp, "%02X", (unsigned)id[ii]);
  }
  fprintf(fp, "\n");
}


int
write_pem_rsa_key_pair(CK_SESSION_HANDLE session_handle, 
		       CK_OBJECT_HANDLE pub_handle, CK_OBJECT_HANDLE priv_handle, 
		       char *keypair_fname)
{
  int ret = -1, mod_len = 0, exp_len = 0;
  CK_RV retCode;
  CK_ATTRIBUTE rsa_modulus_template[2];
  CK_BYTE_PTR n = NULL, exp_val = NULL;
  BIO *outfile = NULL;
  RSA *rsa; 

  rsa_modulus_template[0].type = CKA_MODULUS;
  rsa_modulus_template[0].pValue = NULL_PTR;
  rsa_modulus_template[0].ulValueLen = 0;

  rsa_modulus_template[1].type = CKA_PUBLIC_EXPONENT;
  rsa_modulus_template[1].pValue = NULL_PTR;
  rsa_modulus_template[1].ulValueLen = 0;

  /* create a BIO to be used for writing out the keypair, do it now before we start talking
  * to hardware */ 
  if ((outfile = BIO_new(BIO_s_file())) == NULL) {
    fprintf(stderr, "Cannot create BIO used to write out PEM key pair.\n");
    goto err;
  }

  if (BIO_write_filename(outfile, keypair_fname) <= 0) {
    fprintf(stderr, "Cannot open [%s] for writing.\n", keypair_fname);
    goto err;
  }

  /* extract public key, modulus size first */
  /* Use the private key ALWAYS because we might not have a public key */
  retCode = p11.std->C_GetAttributeValue(session_handle, priv_handle, rsa_modulus_template, 2);
  if(retCode != CKR_OK){
    fprintf(stderr, "Failed to extract modulus size of key pair. err 0x%x\n", (int) retCode);
    goto err;
  }

  /* allocate enough space to extract modulus itself */
  mod_len = rsa_modulus_template[0].ulValueLen;
  n = (CK_BYTE_PTR) malloc(mod_len);
  rsa_modulus_template[0].pValue = n;
  
  /* extract exponent */
  exp_len = rsa_modulus_template[1].ulValueLen;
  exp_val = (CK_BYTE_PTR) malloc(exp_len);
  rsa_modulus_template[1].pValue = exp_val;

  /* extract public key, get modulus */
  /* Use the private key ALWAYS because we might not have a public key */
  retCode = p11.std->C_GetAttributeValue(session_handle, priv_handle, rsa_modulus_template, 2);
  if(retCode != CKR_OK){
    fprintf(stderr, "Failed to extract modulus of key pair. err 0x%x\n", (int) retCode);
    goto err;
  }
  
  if (verbose) {
    luna_dump_hex(stdout, "CKA_MODULUS=", n, mod_len);
    luna_dump_hex(stdout, "CKA_PUBLIC_EXPONENT=", exp_val, exp_len);
  }
 
  /* get us an rsa structure and allocate its components */
  if ((rsa = RSA_new()) == NULL) goto err;
  if ((rsa->n = BN_new()) == NULL) goto err;
  if ((rsa->d = BN_new()) == NULL) goto err;
  if ((rsa->p = BN_new()) == NULL) goto err;
  if ((rsa->q = BN_new()) == NULL) goto err;
  if ((rsa->iqmp = BN_new()) == NULL) goto err;
  if ((rsa->dmq1 = BN_new()) == NULL) goto err;
  if ((rsa->dmp1 = BN_new()) == NULL) goto err;
  /* set em to 1 */
  if (!BN_one(rsa->d)) goto err;
  if (!BN_one(rsa->p)) goto err;
  if (!BN_one(rsa->q)) goto err;
  if (!BN_one(rsa->iqmp)) goto err;
  if (!BN_one(rsa->dmq1)) goto err;
  if (!BN_one(rsa->dmp1)) goto err;

  /* Assign private and public key handles */
  if (priv_handle != (CK_OBJECT_HANDLE)0) {
    if (!BN_set_word(rsa->p, (unsigned long) priv_handle)) goto err;
  }
  
  if (pub_handle != (CK_OBJECT_HANDLE)0) {
    if (!BN_set_word(rsa->q, (unsigned long) pub_handle)) goto err;
  }
  
  /* save the modulus, exponent */
  if (!(rsa->e = BN_bin2bn(exp_val, exp_len, NULL))) goto err;
  if (!(rsa->n = BN_bin2bn(n, mod_len, rsa->n))) goto err;
    
  if (!PEM_write_bio_RSAPrivateKey(outfile, rsa, NULL, NULL, 0, NULL, NULL))
     goto err;
    
  ret = 0;

  if (verbose)
    fprintf(stdout, "Wrote file \"%s\".\n", (char*)keypair_fname);
  
err:

  if (n) 
    free(n);
  
  if (exp_val) 
    free(exp_val);
  
  return ret;
}


#ifndef OPENSSL_NO_DH

int
write_pem_dh_key_pair(CK_SESSION_HANDLE session_handle, 
		      CK_OBJECT_HANDLE pub_handle, CK_OBJECT_HANDLE priv_handle, 
		      const CK_BYTE *dh_prime, const CK_USHORT dh_prime_size,
		      const CK_BYTE *dh_base,  const CK_USHORT dh_base_size,
		      unsigned char *keypair_fname)
{
  int ret = -1, pub_val_len;
  CK_RV retCode;
  CK_ATTRIBUTE dh_pub_value_template[] = { { CKA_VALUE, NULL_PTR, 0 } };
  CK_BYTE_PTR n = NULL;
  BIO *outfile = NULL;
  DH *dh; 
  unsigned char *pub_val;

  
  /* create a BIO to be used for writing out the keypair, do it now before we start talking
  * to hardware */ 
  if ((outfile = BIO_new(BIO_s_file())) == NULL) {
    fprintf(stderr, "Cannot create BIO used to write out PEM key pair.\n");
    goto err;
  }

  if (BIO_write_filename(outfile, keypair_fname) <= 0) {
    fprintf(stderr, "Cannot open [%s] for writing.\n", keypair_fname);
    goto err;
  }

  /* extract public key, modulus size first */
  retCode = p11.std->C_GetAttributeValue(session_handle, pub_handle, dh_pub_value_template, 1);
  if(retCode != CKR_OK){
    fprintf(stderr, "Failed to extract modulus size of key pair. err 0x%x\n", (int) retCode);
    goto err;
  }

  /* allocate enough space to extract public value */
  pub_val_len = dh_pub_value_template[0].ulValueLen;
  pub_val     = (CK_BYTE_PTR) malloc(pub_val_len);
  dh_pub_value_template[0].pValue = pub_val;
  
  /* extract public key */
  retCode = p11.std->C_GetAttributeValue(session_handle, pub_handle, dh_pub_value_template, 1);
  if(retCode != CKR_OK){
    fprintf(stderr, "Failed to extract modulus of key pair. err 0x%x\n", (int) retCode);
    goto err;
  }
 
  /* get us an rsa structure and allocate its components */
  if ((dh = DH_new()) == NULL) goto err;
  if ((dh->p = BN_new()) == NULL) goto err;
  if ((dh->g = BN_new()) == NULL) goto err;
  if ((dh->pub_key = BN_new()) == NULL) goto err;
  if ((dh->priv_key = BN_new()) == NULL) goto err;

  dh->p = BN_bin2bn(dh_prime, dh_prime_size, dh->p); 
  dh->g = BN_bin2bn(dh_base, dh_base_size, dh->g);
  dh->pub_key = BN_bin2bn(pub_val, pub_val_len, dh->pub_key);

#if 0  
  if (!PEM_write_bio_DHPrivateKey(outfile, dh, NULL, NULL, 0, NULL, NULL))
    goto err;
#endif
    
  ret = 0;
  
err:

  if (n) 
    free(n);
  
  return ret;
}

#else

static void op_no_dh()
{
  fprintf(stderr, "Not implemented (source was compiled with OPENSSL_NO_DH defined).\n");
}

int
write_pem_dh_key_pair(CK_SESSION_HANDLE session_handle, 
		      CK_OBJECT_HANDLE pub_handle, CK_OBJECT_HANDLE priv_handle, 
		      const CK_BYTE *dh_prime, const CK_USHORT dh_prime_size,
		      const CK_BYTE *dh_base,  const CK_USHORT dh_base_size,
		      unsigned char *keypair_fname)
{
  op_no_dh();
  return -1;
}

#endif

int
op_generate_dsa_key_pair(CK_SLOT_ID slotid, CK_USHORT modulussize, 
  char *keypair_fname, char *param_fname)
{
  int ret = -1;
  CK_RV retCode = ~CKR_OK;
  CK_ATTRIBUTE *dsa_pub_template = NULL;
  CK_ATTRIBUTE *dsa_priv_template = NULL;
  CK_USHORT dsa_pub_template_size = 0;
  CK_USHORT dsa_priv_template_size = 0;
  CK_OBJECT_HANDLE pub_handle = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE priv_handle = CK_INVALID_HANDLE;
  CK_SESSION_HANDLE session_handle = CK_INVALID_HANDLE;
  CK_BYTE *pubLabel = NULL;
  CK_BYTE *privLabel = NULL;
  DSA *dsaparam = NULL;
  CK_BYTE_PTR bufP = NULL;
  CK_BYTE_PTR bufQ = NULL;
  CK_BYTE_PTR bufG = NULL;
  CK_ULONG lenbufP = 0;
  CK_ULONG lenbufQ = 0;
  CK_ULONG lenbufG = 0;
  
  char szPubLabel[CA3UTIL_MAX_STRING+1];
  char szPrivLabel[CA3UTIL_MAX_STRING+1];
  CK_BYTE baCkId[20];
  
  memset(szPubLabel, 0, sizeof(szPubLabel));
  memset(szPrivLabel, 0, sizeof(szPrivLabel));
  memset(baCkId, 0, sizeof(baCkId));

  ret = set_application_id(app_id_hi, app_id_lo);
  if (ret != 0)
    return -1;
 
  if (param_fname != NULL) {
	/* get p, q, g from file */
	BIO *f = NULL;
    
	if ( (f = BIO_new(BIO_s_file())) == NULL )
		{
		fprintf(stderr, "BIO_new failed. \n");
		return -1;
		}
	
	if (BIO_read_filename(f, param_fname) <= 0)
		{
		fprintf(stderr, "BIO_read_filename failed. \n");
		return -1;
		}

	if ( (dsaparam = PEM_read_bio_DSAparams(f, NULL, NULL, NULL)) == NULL )
		{
		fprintf(stderr, "PEM_read_bio_DSAparams failed. \n");
		return -1;
		}

	bufP = (CK_BYTE_PTR)OPENSSL_malloc(BN_num_bytes(dsaparam->p)); lenbufP = BN_bn2bin(dsaparam->p, bufP);
	bufQ = (CK_BYTE_PTR)OPENSSL_malloc(BN_num_bytes(dsaparam->q)); lenbufQ = BN_bn2bin(dsaparam->q, bufQ);
	bufG = (CK_BYTE_PTR)OPENSSL_malloc(BN_num_bytes(dsaparam->g)); lenbufG = BN_bn2bin(dsaparam->g, bufG);
	modulussize = (lenbufP * 8);
	
  } else {
	/* legacy hardcoded p, q, g */
	bufP = dsa_1024_prime; lenbufP = sizeof(dsa_1024_prime);
	bufQ = dsa_1024_subPrime; lenbufQ = sizeof(dsa_1024_subPrime);
	bufG = dsa_1024_base; lenbufG = sizeof(dsa_1024_base);
	modulussize = (lenbufP * 8);
  }
  
  if (modulussize >= 1024) {
      sautil_sprint_unique(szPubLabel, szPrivLabel, "DSA", modulussize);
      pubLabel  = (CK_BYTE *)szPubLabel;
      privLabel = (CK_BYTE *)szPrivLabel;
  } else {
      fprintf(stderr, "DSA modulus size too small [%u]\n", (unsigned)modulussize);
      return -1;
  }
  
  if (verbose) 
    fprintf(stdout, "Generating %d bit DSA key pair.\n", (int) modulussize);
  
  if (open_session(slotid, &session_handle) != 0)
     return -1;
  
  /* if we're not logged in here, return an error */
  if ( !loggedin( slotid ) )
  {
     fprintf( stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int) slotid );
     return -1;
  }

  /* generate temporary CKA_ID */
  if (sautil_sha1_prng(session_handle, baCkId) != CKR_OK) {
     fprintf(stderr, "Failed RNG.\n");
     return -1;
  }

  ret = init_dsa_key_template(&dsa_pub_template, &dsa_priv_template, &dsa_pub_template_size, &dsa_priv_template_size, 
			      pubLabel, privLabel,
                              bufP, lenbufP,
			      bufQ, lenbufQ,
			      bufG, lenbufG,
			      baCkId, sizeof(baCkId));
  if (ret != 0)
    return -1;

  /* C_GenerateKeyPair */
  if (1) {
    CK_MECHANISM dsa_key_gen_mech = { CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };

    retCode = p11.std->C_GenerateKeyPair(session_handle, &dsa_key_gen_mech,
                              dsa_pub_template, dsa_pub_template_size,
                              dsa_priv_template, dsa_priv_template_size,
                              &pub_handle, &priv_handle);
  }
  
  if (retCode != CKR_OK) {
    fprintf(stderr, "Generate DSA Key Pair Error 0x%x.\n", (int) retCode);
    if (retCode == CKR_DEVICE_ERROR)
      fprintf(stderr, "  Device Error. Not logged in with -o?\n");
    goto err;
  }

  if (verbose) { 
    fprintf(stdout, "DSA Public key handle is %u\n", (unsigned) pub_handle);
    fprintf(stdout, "DSA Private key handle is %u\n", (unsigned) priv_handle);
  }

  /* FIXME: CKA_ID should be derived from public key */
  if (verbose) { 
    luna_dump_hex(stdout, "CKA_ID=", baCkId, sizeof(baCkId));
  }

  ret = write_pem_dsa_key_pair(session_handle, pub_handle, priv_handle, 
			       keypair_fname);
  if (ret != 0)
    goto err;

  sautil_ckatab_free_all(dsa_pub_template, dsa_pub_template_size);
  sautil_ckatab_free_all(dsa_priv_template, dsa_priv_template_size);
  return 0;
  
err:
  sautil_ckatab_free_all(dsa_pub_template, dsa_pub_template_size);
  sautil_ckatab_free_all(dsa_priv_template, dsa_priv_template_size);
  close_session(session_handle); session_handle = 0;
  return -1;
}

int
op_generate_rsa_key_pair(CK_SLOT_ID slotid, CK_USHORT modulussize, char *keypair_fname)
{
  int ret;
  CK_RV retCode;
  CK_ATTRIBUTE *rsa_pub_template;
  CK_ATTRIBUTE *rsa_priv_template;
  CK_USHORT rsa_pub_template_size, rsa_priv_template_size;
  CK_OBJECT_HANDLE pub_handle, priv_handle;
  CK_SESSION_HANDLE session_handle;
  
  CK_BYTE arrExponent3[1] = { 0x03 };
  CK_BYTE arrExponent4[3] = { 0x01, 0x00, 0x01 };
  CK_BYTE *ptrExponent = NULL;
  int countofExponent = 0;

  CK_BYTE *pubLabel = NULL, *privLabel = NULL;
  char szPubLabel[CA3UTIL_MAX_STRING+1];
  char szPrivLabel[CA3UTIL_MAX_STRING+1];
  CK_BYTE baCkId[20];

  memset(szPubLabel, 0, sizeof(szPubLabel));
  memset(szPrivLabel, 0, sizeof(szPrivLabel));
  memset(baCkId, 0, sizeof(baCkId));

  ret = set_application_id(app_id_hi, app_id_lo);
  if (ret != 0)
    return -1;

  sautil_sprint_unique(szPubLabel, szPrivLabel, "RSA", modulussize);
  pubLabel  = (CK_BYTE *)szPubLabel;
  privLabel = (CK_BYTE *)szPrivLabel;

  switch (optSelExponent) {
  case OPT_SEL_EXP3:
     ptrExponent = arrExponent3;
     countofExponent = sizeof(arrExponent3);
     break;
  case OPT_SEL_EXP4:
     ptrExponent = arrExponent4;
     countofExponent = sizeof(arrExponent4);
     break;
  case OPT_SEL_EXPOTHER:
     ptrExponent = bpOptSelExponent;
     countofExponent = countofOptSelExponent;
     break;
  case OPT_SEL_EXPNULL:
  default:
     break;
  }
  
  if (open_session(slotid, &session_handle) != 0)
     return -1;
  
  /* if we're not logged in here, return an error */
  if ( !loggedin( slotid ) )
  {
     fprintf( stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int) slotid );
     return -1;
  }

  /* generate temporary CKA_ID */
  if (sautil_sha1_prng(session_handle, baCkId) != CKR_OK) {
     fprintf(stderr, "Failed RNG.\n");
     return -1;
  }

  /* init tmeplate */
  ret = init_rsa_key_template(&rsa_pub_template, &rsa_priv_template, &rsa_pub_template_size, &rsa_priv_template_size, 
                          modulus_size, ptrExponent, countofExponent,
			  privLabel, pubLabel, 
			  baCkId, sizeof(baCkId));  
  if (ret != 0)
    return -1;

  /* C_GenerateKeyPair */ 
  if (verbose) 
    fprintf(stdout, "Generating %d bit RSA key pair.\n", (int) modulussize);

  if (1) {  
    CK_MECHANISM rsa_key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

    retCode = p11.std->C_GenerateKeyPair(session_handle, &rsa_key_gen_mech,
                              rsa_pub_template, rsa_pub_template_size,
                              rsa_priv_template, rsa_priv_template_size,
                              &pub_handle, &priv_handle);
  }
  
  if (retCode != CKR_OK) {
    fprintf(stderr, "Generate Key Pair Error 0x%x.\n", (int) retCode);
    switch (retCode) {
    case CKR_DEVICE_ERROR:
      fprintf(stderr, "  Device Error. [Hint: is user logged in with sautil -o ?] \n");
      break;
    case CKR_ATTRIBUTE_VALUE_INVALID:
      fprintf(stderr, "  Attribute Value Invalid.  [Hint: is modulus size %u supported by HSM ?] \n", (unsigned)modulussize);
      break;
    }
    goto err;
  }

  if (verbose) { 
    fprintf(stdout, "RSA Public key handle is %u\n", (unsigned) pub_handle); 
    fprintf(stdout, "RSA Private key handle is %u\n", (unsigned) priv_handle); 
    fprintf(stdout, "CKA_LABEL=%s\n", (char*) szPrivLabel); 
  }
 
  /* Change CKA_ID from SHA1(pseudo_random_bytes) to SHA1(modulus_without_leading_zero_bytes) */
  {
    CK_RV ckrv = CKR_OK;
    CK_BYTE idSha1[20];

    /* Get CKA_MODULUS */
    {
      CK_ATTRIBUTE attrib[1];
      memset(attrib, 0, sizeof(attrib));
      attrib[0].type = CKA_MODULUS;
      attrib[0].pValue = NULL;
      attrib[0].ulValueLen = 0;
      ckrv = p11.std->C_GetAttributeValue(session_handle, pub_handle, attrib, 1);
      if (ckrv == CKR_OK) {
        attrib[0].pValue = (CK_BYTE_PTR)OPENSSL_malloc(attrib[0].ulValueLen);
        if (!attrib[0].ulValueLen || attrib[0].pValue==NULL || (attrib[0].ulValueLen > (8192*2))) {
          ckrv = CKR_GENERAL_ERROR;
        }
      }
      if (ckrv == CKR_OK) {
        ckrv = p11.std->C_GetAttributeValue(session_handle, pub_handle, attrib, 1);
      }
      if (ckrv == CKR_OK) {
        BIGNUM *bn = BN_bin2bn((unsigned char *)attrib[0].pValue, attrib[0].ulValueLen, NULL);
        char* szBn = NULL;
        unsigned ii = 0;
        if (bn==NULL) {
          ckrv = CKR_GENERAL_ERROR;
        } else {
          for (ii = 0; ii < attrib[0].ulValueLen; ii++) { /* strip leading zeroes */
            if (((unsigned char*)attrib[0].pValue)[ii] != 0) {
              break;
            }
          }
          (void)SHA1(&((unsigned char*)attrib[0].pValue)[ii], (attrib[0].ulValueLen - ii), idSha1);
        }
        if (bn != NULL) { OPENSSL_free(bn); bn = NULL; }
        if (szBn != NULL) { OPENSSL_free(szBn); szBn = NULL; }
      }
      if (ckrv != CKR_OK) {
        fprintf(stderr, "  WARNING: trouble reading CKA_ID. \n");
      }
      if (attrib[0].pValue != NULL) { OPENSSL_free(attrib[0].pValue); attrib[0].pValue = NULL; }
    }
   
    /* Set CKA_ID */
    if (ckrv == CKR_OK) {
      CK_ATTRIBUTE attrib[1];
      memset(attrib, 0, sizeof(attrib));
      attrib[0].type = CKA_ID;
      attrib[0].pValue = idSha1;
      attrib[0].ulValueLen = sizeof(idSha1);
      ckrv = p11.std->C_SetAttributeValue(session_handle, priv_handle, attrib, 1);
      if (ckrv == CKR_OK) {
        ckrv = p11.std->C_SetAttributeValue(session_handle, pub_handle, attrib, 1);
      }
      if (ckrv != CKR_OK) {
        fprintf(stderr, "  WARNING: trouble writing CKA_ID. \n");
      } else {
        if (verbose) { 
          luna_dump_hex(stdout, "CKA_ID=", idSha1, sizeof(idSha1));
        }
      }
    }
  }
 
  ret = write_pem_rsa_key_pair(session_handle, pub_handle, priv_handle, keypair_fname);
  if (ret != 0)
    goto err;

 
  return 0;
  
err:
  close_session(session_handle); session_handle = 0;
  return -1;
}


#ifdef CA3UTIL_DIFFIE_HELLMAN

int
op_generate_dh_key_pair(CK_SLOT_ID slotid, CK_USHORT size, char *keypair_fname)
{
  DH *dh;
  int ret, retc = -1;
  CK_RV retCode;
  CK_ATTRIBUTE      *dh_pub_template, *dh_priv_template;
  CK_USHORT         dh_pub_template_size, dh_priv_template_size;
  CK_OBJECT_HANDLE  pub_handle, priv_handle;
  CK_SESSION_HANDLE session_handle;
  unsigned char *base = NULL, *prime = NULL;
  int base_len, prime_len;
  
  ret = set_application_id(app_id_hi, app_id_lo);
  if (ret != 0)
    return -1;
  if (open_session(slotid, &session_handle) != 0)
    return -1; 
 
  /* if we're not logged in here, return an error */
  if ( !loggedin( slotid ) )
  {
     fprintf( stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int) slotid );
     return -1;
  }

  dh = DH_generate_parameters(size, DH_GENERATOR_2, NULL, NULL);
  if (!dh) {
    fprintf(stderr, "Failed to generate DH parameters for %ubit key.\n", (unsigned)size);
    return -1;
  }
  
  base  = (unsigned char *)malloc (BN_num_bytes(dh->p));
  prime = (unsigned char *)malloc (BN_num_bytes(dh->g));
    
  prime_len = BN_bn2bin(dh->p, prime);
  base_len  = BN_bn2bin(dh->g, base);
  
  ret = init_dh_key_template(&dh_pub_template, &dh_priv_template, &dh_pub_template_size, &dh_priv_template_size,
			     (CK_BYTE_PTR)"Public DH key", (CK_BYTE_PTR)"Private DH key",
			     prime, prime_len, base, base_len);

  if (ret != 0)
    goto err;

  if (verbose) 
    fprintf(stdout, "Generating %u bit DH key pair.\n", (unsigned)size);
  

  if (1) {
    CK_MECHANISM dh_key_gen_mech =  { CKM_DH_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
 
    retCode = p11.std->C_GenerateKeyPair(session_handle, &dh_key_gen_mech,
                              dh_pub_template, dh_pub_template_size,
                              dh_priv_template, dh_priv_template_size,
                              &pub_handle, &priv_handle);
  }
  
  if (retCode != CKR_OK) {
    fprintf(stderr, "Generate DH Key Pair Error 0x%x.\n", (int) retCode);
    if (retCode == CKR_DEVICE_ERROR)
      fprintf(stderr, "  Device Error. Not logged in with -o?\n");
    goto err;
  }

  if (verbose) { 
    fprintf(stdout, "DH Public  key handle is %u\n", (unsigned) pub_handle);
    fprintf(stdout, "DH Private key handle is %u\n", (unsigned) priv_handle);
  }
 
  ret = write_pem_dh_key_pair(session_handle, pub_handle, priv_handle, keypair_fname);
  if (ret != 0)
    goto err;
 
  retc = 0;
    
err:

  if (base) free (base);
  if (prime) free (prime);
  close_session(session_handle); session_handle = 0;
  return retc;
}

#endif /* CA3UTIL_DIFFIE_HELLMAN */



CK_OBJECT_HANDLE
luna_find_dsa_handle(CK_SESSION_HANDLE session_handle, DSA *dsa, short flagPrivate)
{   
  int id_val_len;
  CK_RV retCode;
  char *bufP, *bufQ, *bufG, *bufPub;
  CK_ATTRIBUTE attrib[6];
  CK_OBJECT_HANDLE handle = 0;
  CK_USHORT obj_count = 0;
  CK_BYTE_PTR id_val = NULL;
  CK_ULONG ulClass = 0;
  CK_ATTRIBUTE dsa_id_value_template[] = { { CKA_ID, NULL_PTR, 0 } };

  bufP   = (char *)OPENSSL_malloc(BN_num_bytes(dsa->p));
  bufQ   = (char *)OPENSSL_malloc(BN_num_bytes(dsa->q));
  bufG   = (char *)OPENSSL_malloc(BN_num_bytes(dsa->g));
  bufPub = (char *)OPENSSL_malloc(BN_num_bytes(dsa->pub_key));

  attrib[0].type = CKA_PRIME;
  attrib[0].pValue = bufP;
  attrib[0].ulValueLen = BN_bn2bin(dsa->p, (unsigned char*)attrib[0].pValue);

  attrib[1].type = CKA_SUBPRIME;
  attrib[1].pValue = bufQ;
  attrib[1].ulValueLen = BN_bn2bin(dsa->q, (unsigned char*)attrib[1].pValue);

  attrib[2].type = CKA_BASE;
  attrib[2].pValue = bufG;
  attrib[2].ulValueLen = BN_bn2bin(dsa->g, (unsigned char*)attrib[2].pValue);

  attrib[3].type = CKA_VALUE;
  attrib[3].pValue = bufPub;
  attrib[3].ulValueLen = BN_bn2bin(dsa->pub_key, (unsigned char*)attrib[3].pValue);


  if (flagPrivate) {
    ulClass = CKO_PRIVATE_KEY;
    attrib[4].type = CKA_CLASS;
    attrib[4].pValue = &ulClass;
    attrib[4].ulValueLen = sizeof(ulClass);
  } else {
    ulClass = CKO_PUBLIC_KEY;
    attrib[4].type = CKA_CLASS;
    attrib[4].pValue = &ulClass;
    attrib[4].ulValueLen = sizeof(ulClass);
  }

  /* Find public object first. */
  retCode = p11.std->C_FindObjectsInit(session_handle, attrib, (flagPrivate) ? 4 : 5);
  if (retCode != CKR_OK) {
    fprintf(stderr, "C_FindObjectInit: Unable to initialize search for a %s DSA key object err 0x%x\n", (flagPrivate) ? "private" :
	    "public", (int) retCode);
    goto err;
  }

  retCode = p11.std->C_FindObjects(session_handle, &handle, 1, &obj_count);
  if (retCode != CKR_OK) {
    fprintf(stderr, "C_FindObject: unable to find a %s DSA key object. err 0x%x\n", (flagPrivate) ? "private" : "public",
	    (int) retCode);
    goto err;
  }

  if (!obj_count) {
    fprintf(stderr, "Token does not contain specified DSA keypair.\n");
    goto err;
  }
  /* Need to perform additional searching when looking for flagPrivate key handles. 
  * We do not have the flagPrivate value and PKCS11 does not allow searching of flagPrivate
  * DSA objects based on their public values. We use instead a unique CKA_ID attribute
  * set during dsa keygen. This ID is shared by pub/priv dsa keys. First extract the
  * CKA_ID from the correct public key, then search for a flagPrivate one keyed by that value */

  if (flagPrivate) {

    /* Extract its CKA_ID attribute unique for a dsa key pair */
    retCode = p11.std->C_GetAttributeValue(session_handle, handle, dsa_id_value_template, 1);
    if(retCode != CKR_OK) {
      fprintf(stderr, "Failed to extract size of DSA keypair ID value. err 0x%x\n", (int) retCode);
      goto err;
    }
    /* allocate enough space to extract the ID value itself */
    id_val_len = dsa_id_value_template[0].ulValueLen;
    id_val = (CK_BYTE_PTR) malloc(id_val_len);
    dsa_id_value_template[0].pValue = id_val;
    /* extract the ID value */
    retCode = p11.std->C_GetAttributeValue(session_handle, handle, dsa_id_value_template, 1);
    if(retCode != CKR_OK) {
      fprintf(stderr, "Failed to extract DSA keypair ID value . err 0x%x\n", (int) retCode);
      goto err;
    }


    ulClass = CKO_PRIVATE_KEY;
    attrib[3].type = CKA_CLASS;
    attrib[3].pValue = &ulClass;
    attrib[3].ulValueLen = sizeof(ulClass);

    attrib[4].type = CKA_ID;
    attrib[4].pValue = id_val;
    attrib[4].ulValueLen = id_val_len;

    /* Find public object first. */
    retCode = p11.std->C_FindObjectsInit(session_handle, attrib, 5);
    if (retCode != CKR_OK) {
      fprintf(stderr, "C_FindObjectInit: Unable to initialize search for a %s DSA key object err 0x%x\n",
	      (flagPrivate) ? "private" : "public", (int) retCode);
      goto err;
    }

    retCode = p11.std->C_FindObjects(session_handle, &handle, 1, &obj_count);
    if (retCode != CKR_OK) {
      fprintf(stderr, "C_FindObject: unable to find a %s DSA key object. err 0x%x\n",
	      (flagPrivate) ? "private" : "public", (int) retCode);
      goto err;
    }
  }

  if (!obj_count)
    handle = 0;

err:

  OPENSSL_free(bufP);
  OPENSSL_free(bufQ);
  OPENSSL_free(bufG);
  OPENSSL_free(bufPub);

  return (CK_OBJECT_HANDLE) handle;
}



/* set private to indicate you are looking for a private key */
/* reset to 0 to look for a public */
static CK_OBJECT_HANDLE
luna_find_rsa_handle(CK_SESSION_HANDLE session_handle, RSA *rsa, short flagPrivate)
{   
  CK_OBJECT_CLASS keyclassPublic = CKO_PUBLIC_KEY;
  CK_OBJECT_CLASS keyclassPrivate = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keytypeRSA = CKK_RSA;

  CK_RV retCode;
  BIGNUM *n, *e;
  char *bufN, *bufE; 
  CK_OBJECT_HANDLE handle = 0;
  CK_USHORT obj_count = 0;
  unsigned ndx = 0;
  CK_ATTRIBUTE attrib[4];

  n = rsa->n;
  e = rsa->e;

  bufN = (char *)OPENSSL_malloc(BN_num_bytes(n));
  bufE = (char *)OPENSSL_malloc(BN_num_bytes(e));

  if (flagPrivate) {
    attrib[ndx=0].type = CKA_CLASS;
    attrib[ndx].pValue = (CK_BYTE_PTR)&keyclassPrivate;
    attrib[ndx].ulValueLen = sizeof(keyclassPrivate);  
  } else {
    attrib[ndx=0].type = CKA_CLASS;
    attrib[ndx].pValue = (CK_BYTE_PTR)&keyclassPublic;
    attrib[ndx].ulValueLen = sizeof(keyclassPublic);  
  }

  attrib[ndx=1].type = CKA_KEY_TYPE;
  attrib[ndx].pValue = (CK_BYTE_PTR)&keytypeRSA;
  attrib[ndx].ulValueLen = sizeof(keytypeRSA);  

  attrib[ndx=2].type = CKA_PUBLIC_EXPONENT;
  attrib[ndx].pValue = (CK_BYTE_PTR)bufE;
  attrib[ndx].ulValueLen = BN_bn2bin(e, (unsigned char*)attrib[2].pValue);

  attrib[ndx=3].type = CKA_MODULUS;
  attrib[ndx].pValue = (CK_BYTE_PTR)bufN;
  attrib[ndx].ulValueLen = BN_bn2bin(n, (unsigned char*)attrib[3].pValue);

  retCode = p11.std->C_FindObjectsInit(session_handle, attrib, 4);
  if (retCode != CKR_OK) {
    fprintf(stderr, "C_FindObjectInit: Unable to initialize search for a %s RSA key object err 0x%x\n", (flagPrivate) ?
	    "private" : "public", (int) retCode);
    goto err;
  }

  retCode = p11.std->C_FindObjects(session_handle, &handle, 1, &obj_count);
  if (retCode != CKR_OK) {
    fprintf(stderr, "C_FindObject: unable to find %s RSA key object. err 0x%x\n", (flagPrivate) ?
	    "private" : "public", (int) retCode);
    goto err;
  }

  if (!obj_count)
    handle = 0;

err:

  OPENSSL_free(bufN);
  OPENSSL_free(bufE);

  return (CK_OBJECT_HANDLE) handle;

}



static int
op_delete_dsa_key_pair(CK_SLOT_ID slotid, char *keypair_fname)
{
  BIO *f = NULL;
  int ret = -1;
  DSA *dsa = NULL;
  CK_OBJECT_HANDLE handle;
  CK_SESSION_HANDLE session_handle;
  CK_RV retCode;
   
 /* create a BIO to be used for writing out the keypair, do it now before we start talking
  * to hardware */
 if ((f = BIO_new(BIO_s_file())) == NULL) {
   fprintf(stderr, "Cannot create BIO used to read DSA PEM key pair.\n");
   goto err;
 }

 if (BIO_read_filename(f, keypair_fname) <= 0) {
   fprintf(stderr, "Cannot open [%s] for reading.\n", keypair_fname);
   goto err;
 }
 
 if (!(dsa = PEM_read_bio_DSAPrivateKey(f, NULL, NULL, NULL))) {
   fprintf(stderr, "Failed reading DSA key pair. file: [%s]\n", keypair_fname);
   goto err;
 }
 
 if (set_application_id(app_id_hi, app_id_lo) != 0)
   goto err;
 if (open_session(slotid, &session_handle) != 0)
   goto err;

  /* if we're not logged in here, return an error */
  if ( !loggedin( slotid ) )
  {
     fprintf( stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int) slotid );
     goto err;
  }

 /* ALWAYS Destroy private object first, if the public dsa key is erased first
  * then we wont be able to find the private one */
 handle = luna_find_dsa_handle(session_handle, dsa, 1);
 if ( (handle == CK_INVALID_HANDLE)
   || ((retCode = p11.std->C_DestroyObject(session_handle, handle)) != CKR_OK) ) {
   fprintf(stderr, "Delete private failed.\n");
   goto err;
 }

  if (verbose) { 
    fprintf(stdout, "DSA private key handle is %u\n", (unsigned) handle);
  }

 fprintf(stderr, "Delete private ok.\n");
 
 /* Destroy public object */
 handle = luna_find_dsa_handle(session_handle, dsa, 0);
 if ( (handle == CK_INVALID_HANDLE)
   || ((retCode = p11.std->C_DestroyObject(session_handle, handle)) != CKR_OK) ) {
   fprintf(stderr, "Delete public failed.\n");
   goto err;
 }
 
  if (verbose) { 
    fprintf(stdout, "DSA public key handle is %u\n", (unsigned) handle);
  }
 
 fprintf(stderr, "Delete public ok.\n");

 ret = 0;
 
err:
 if (dsa) DSA_free(dsa);
 BIO_free(f); 
 
  return ret;
}

int
op_delete_rsa_key_pair(CK_SLOT_ID slotid, char *keypair_fname)
{
 BIO *f = NULL;
 int ret = -1;
 RSA *rsa = NULL;  
 CK_OBJECT_HANDLE handle;
 CK_SESSION_HANDLE session_handle;
 CK_RV retCode;
   
 /* create a BIO to be used for writing out the keypair, do it now before we start talking
  * to hardware */
 if ((f = BIO_new(BIO_s_file())) == NULL) {
   fprintf(stderr, "Cannot create BIO used to read RSA PEM key pair.\n");
   goto err;
 }

 if (BIO_read_filename(f, keypair_fname) <= 0) {
   fprintf(stderr, "Cannot open [%s] for reading.\n", keypair_fname);
   goto err;
 }
 
 if (!(rsa = PEM_read_bio_RSAPrivateKey(f, NULL, NULL, NULL))) {
   fprintf(stderr, "Failed reading RSA key pair. file: [%s]\n", keypair_fname);
   goto err;
 }

 if (set_application_id(app_id_hi, app_id_lo) != 0)
   goto err;
 if (open_session(slotid, &session_handle) != 0)
   goto err;

  /* if we're not logged in here, return an error */
  if ( !loggedin( slotid ) )
  {
     fprintf( stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int) slotid );
     goto err;
  }

 /* Destroy public object */
 handle = luna_find_rsa_handle(session_handle, rsa, 0);
 if ( (handle == CK_INVALID_HANDLE)
   || ((retCode = p11.std->C_DestroyObject(session_handle, handle)) != CKR_OK) ) {
   fprintf(stderr, "Delete public failed.\n");
   goto err;
 }

  if (verbose) { 
    fprintf(stdout, "RSA public key handle is %u\n", (unsigned) handle);
  }
 
 fprintf(stderr, "Delete public ok.\n");

 /* Destroy private object */
 handle = luna_find_rsa_handle(session_handle, rsa, 1);
 if ( (handle == CK_INVALID_HANDLE)
   || ((retCode = p11.std->C_DestroyObject(session_handle, handle)) != CKR_OK) ) {
   fprintf(stderr, "Delete private failed.\n");
   goto err;
 }

  if (verbose) { 
    fprintf(stdout, "RSA private key handle is %u\n", (unsigned) handle);
  }
 
 fprintf(stderr, "Delete private ok.\n");
 ret = 0;
 
err:
 if (rsa) RSA_free(rsa);
 BIO_free(f); 
    
 return ret;
}


int
main(int argc, char *argv[])
{
  CK_RV retCode = CKR_OK;

  /* zero init global data */
  memset(sautil_password, 0, sizeof(sautil_password));
  memset(sautil_szcurve, 0, sizeof(sautil_szcurve));

  /* parse command line */
  if (parse_args(argc, argv) != 0) {
    goto err;
  }

  /* NOTE: dont print anything until we had a chance to parse arguments (see parse_args) */
  fprintf(stderr, "Copyright (C) 2009 SafeNet, Inc. All rights reserved.\n");
  fprintf(stderr, LOCAL_APP_NAME "is the property of SafeNet, Inc. and is provided to our customers for\n");
  fprintf(stderr, "the purpose of diagnostic and development only.  Any re-distribution of this\n");
  fprintf(stderr, "program in whole or in part is a violation of the license agreement.\n\n");

  if ( (retCode = sautil_init()) != CKR_OK ) {
    /* fprintf(stderr, "C_Initialize Error: 0x%x.\n", (int) retCode); */
    goto err;
  }

  /* Check for a session open request */
  if (operation & OP_OPEN) {
    if (strlen(sautil_password) < 4) {
      fprintf(stderr, "At least 4 characters must be entered to attempt Login.\n");
      goto err;
    }
    if (op_open_app_id(slot_id, app_id_hi, app_id_lo) != 0)
      goto err;
  }

  /* Check if a key delete operation was requested */  
  if (operation & OP_DELETE_RSA_KEY_PAIR) {
    if (!key_filename) {
      fprintf(stderr, "Use -f to specify RSA key pair to be deleted.\n");
      goto err;
    }
    if (op_delete_rsa_key_pair(slot_id, key_filename) != 0) 
      goto err;
  } else 
  if (operation & OP_DELETE_DSA_KEY_PAIR) {
    if (!key_filename) {
      fprintf(stderr, "Use -f to specify DSA key pair to be deleted.\n");
      goto err;
    }
    if (op_delete_dsa_key_pair(slot_id, key_filename) != 0)
      goto err;
  } 
#if defined(LUNA_OSSL_ECDSA)
  if (operation & OP_DELETE_ECDSA_KEY_PAIR) {
    if (!key_filename) {
      fprintf(stderr, "Use -m to specify ECDSA key pair to be deleted.\n");
      goto err;
    }
    if (op_delete_ecdsa_key_pair(slot_id, key_filename) != 0)
      goto err;
  } 
#endif /* LUNA_OSSL_ECDSA */

  /* Check for RSA or DSA key generation request */  
  if (operation & OP_GENERATE_RSA_KEY_PAIR) {
    if (!key_filename) {
      fprintf(stderr, "No key pair output filename specified.\n");
      goto err;
    }
    if (op_generate_rsa_key_pair(slot_id, modulus_size, key_filename) != 0) {
      goto err;
    }
  } else
  if (operation & OP_GENERATE_DSA_KEY_PAIR) {
    if (!key_filename) {
      fprintf(stderr, "No key pair output filename specified.\n");
      goto err;
    }
    if (op_generate_dsa_key_pair(slot_id, modulus_size, key_filename, key_paramfile) != 0) {
      goto err;
    }
  }
#if defined(LUNA_OSSL_ECDSA)
  if (operation & OP_GENERATE_ECDSA_KEY_PAIR) {
    if (!key_filename) {
      fprintf(stderr, "No key pair output filename specified.\n");
      goto err;
    }
    if (op_generate_ecdsa_key_pair(slot_id, modulus_size, key_filename, key_paramfile) != 0) {
      goto err;
    }
  }
#endif /* LUNA_OSSL_ECDSA */
#ifdef CA3UTIL_DIFFIE_HELLMAN
  if (operation & OP_GENERATE_DH_KEY_PAIR) {
    if (!key_filename) {
      fprintf(stderr, "No key pair output filename specified.\n");
      goto err;
    }
    if (op_generate_dh_key_pair(slot_id, modulus_size, key_filename) != 0) {
      goto err;
    }

  }
#endif /* CA3UTIL_DIFFIE_HELLMAN */
  if (operation & OP_RESTORE_KEYFILE) {
    if (!key_filename) {
      fprintf(stderr, "No filename specified.\n");
      goto err;
    }
    if (!key_keytype) {
      fprintf(stderr, "No keytype specified (RSA, DSA, ECDSA).\n");
      goto err;
    }
    if ( strcmp(key_keytype, "RSA") && strcmp(key_keytype, "DSA") && strcmp(key_keytype, "ECDSA") ) {
      fprintf(stderr, "Unrecognized keytype [%s].\n", (char*)key_keytype);
      goto err;
    }
    if (luna_restore_keyfile(slot_id, (CK_OBJECT_HANDLE)key_handle, key_filename, key_keytype) != 0) {
      goto err;
    }
  }

  if (operation & OP_CLOSE) {
    if (op_close_app_id(slot_id, app_id_hi, app_id_lo) != 0)
      goto err;
  }
 
  sautil_exit(0);
  
err:

  sautil_exit(-1);
}


#ifndef SAUTIL_HAVE_OPTARG

/* Argument list parsing */
static int lunaOptNdx = 1;

int getopt(int argc, char * const argv[], const char *optstring)
{
   char *sArg = 0;

   optarg = 0;
   if (lunaOptNdx >= argc) return EOF;
   sArg = argv[lunaOptNdx++];
   if ( !sArg ) return EOF;
   if ( !strchr("-/", (int)sArg[0]) ) return EOF;
   if ( (sArg[1] == '\0') ) return EOF;
   if ( !strchr(optstring, (int)sArg[1]) ) return EOF;
   if ( (sArg[2] != '\0') ) {
      /* e.g., "sautil -s1" */
      optarg = &sArg[2];
      return (int)sArg[1];
   }
   if (lunaOptNdx >= argc) {
      /* e.g., "sautil -s12" */
      return (int)sArg[1];
   }
   if ( !strchr("-/", (int)argv[lunaOptNdx][0]) ) {
      /* e.g., "sautil -s 12" */
      optarg = &argv[lunaOptNdx++][0];
      return (int)sArg[1];
   }
   return (int)sArg[1];
}

#endif


int luna_find_private_rsa(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle, CK_OBJECT_HANDLE_PTR pprivate);

/* Restore keyfile given RSA public key handle */
int luna_restore_keyfile(CK_SLOT_ID slotid, CK_OBJECT_HANDLE some_handle, char *keypair_fname, char *szkeytype)
{
  int ret = 0;
  CK_SESSION_HANDLE session_handle = 0;

  ret = set_application_id(app_id_hi, app_id_lo);
  if (ret != 0)
    return -1;
  
  if (open_session(slotid, &session_handle) != 0)
     return -1;
  
  /* if we're not logged in here, return an error */
  if ( !loggedin( slotid ) )
  {
     fprintf( stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int) slotid );
     return -1;
  }

  if (some_handle==0) {
      some_handle = (luna_select_key(session_handle, &some_handle, szkeytype)) ? 0 : some_handle;
  }
  
  if (some_handle==0) {
      fprintf(stderr, "Error: %s key handle cannot be zero.\n", (char*)szkeytype);
      return -1;
  }

  if (verbose) { 
    fprintf(stdout, "%s key handle is %d\n", (char*)szkeytype, (int) some_handle);
  }

  ret = -1;
  if (strcmp(szkeytype, "RSA") == 0) {
    ret = write_pem_rsa_key_pair(session_handle, 0, some_handle, keypair_fname);
  }
  if (strcmp(szkeytype, "DSA") == 0) {
    ret = write_pem_dsa_key_pair(session_handle, some_handle, 0, keypair_fname);
  }
#if defined(LUNA_OSSL_ECDSA)
  if (strcmp(szkeytype, "ECDSA") == 0) {
    ret = write_pem_ecdsa_key_pair(session_handle, some_handle, 0, keypair_fname);
  }
#endif /* LUNA_OSSL_ECDSA */
  
  if (ret != 0)
    goto err;
 
  return 0;
  
err:
  close_session(session_handle); session_handle = 0;
  return -1;
}


/* luna_rsa_attributes */
typedef struct
{
    CK_ATTRIBUTE attr[2];
    CK_ATTRIBUTE_PTR modulus;
    CK_ATTRIBUTE_PTR exponent;

} luna_rsa_attributes;

int luna_read_rsa_public_attributes(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle, luna_rsa_attributes* lpattr);
int luna_find_rsa_private_handle(CK_SESSION_HANDLE session_handle, luna_rsa_attributes* lpattr, int flagPrivate, CK_OBJECT_HANDLE_PTR priv_handle_ptr);
void luna_rsa_attributes_init(luna_rsa_attributes* lpattr);
void luna_rsa_attributes_fini(luna_rsa_attributes* lpattr);

/* Find private key handle */
int luna_find_private_rsa(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle, CK_OBJECT_HANDLE_PTR pprivate)
{
    CK_OBJECT_HANDLE apublic = 0;
    luna_rsa_attributes attrRsa;

    luna_rsa_attributes_init(&attrRsa);
    if (luna_read_rsa_public_attributes(session_handle, pub_handle, &attrRsa)) {
        fprintf(stderr, "Error reading RSA public attributes.\n");
        return 1;
    }
    if (luna_find_rsa_private_handle(session_handle, &attrRsa, 1, pprivate)) {
        fprintf(stderr, "Error finding RSA private handle.\n");
        return 1;
    }
    if (luna_find_rsa_private_handle(session_handle, &attrRsa, 0, &apublic)) {
        fprintf(stderr, "Error finding RSA public handle.\n");
        return 1;
    }
    if (apublic!=pub_handle) {
        fprintf(stderr, "Expected RSA public key.\n");
        return 1;
    }
    if (apublic==(*pprivate)) {
        fprintf(stderr, "Search found public = private.\n");
        return 1;
    }
    luna_rsa_attributes_fini(&attrRsa);
    return 0;
}

/* Find public key handle */
int luna_find_public_rsa(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE priv_handle, CK_OBJECT_HANDLE_PTR ppublic)
{
    CK_OBJECT_HANDLE aprivate = 0;
    luna_rsa_attributes attrRsa;

    luna_rsa_attributes_init(&attrRsa);
    if (luna_read_rsa_public_attributes(session_handle, priv_handle, &attrRsa)) {
        fprintf(stderr, "Error reading RSA public attributes.\n");
        return 1;
    }
    if (luna_find_rsa_private_handle(session_handle, &attrRsa, 1, &aprivate)) {
        fprintf(stderr, "Error finding RSA private handle.\n");
        return 1;
    }
    if (luna_find_rsa_private_handle(session_handle, &attrRsa, 0, ppublic)) {
        fprintf(stderr, "Error finding RSA public handle.\n");
        return 1;
    }
    if (aprivate!=priv_handle) {
        fprintf(stderr, "Expected RSA private key.\n");
        return 1;
    }
    if (aprivate==(*ppublic)) {
        fprintf(stderr, "Search found public = private.\n");
        return 1;
    }
    luna_rsa_attributes_fini(&attrRsa);
    return 0;
}

/* Read public key attributes */
int luna_read_rsa_public_attributes(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle, luna_rsa_attributes* lpattr)
{
    lpattr->modulus->type = CKA_MODULUS;
    lpattr->modulus->pValue = NULL_PTR;
    lpattr->modulus->ulValueLen = 0;

    lpattr->exponent->type = CKA_PUBLIC_EXPONENT;
    lpattr->exponent->pValue = NULL_PTR;
    lpattr->exponent->ulValueLen = 0;

    if (luna_get_attribute(session_handle, pub_handle, lpattr->modulus)) {
        return 1;
    }
    if (luna_get_attribute(session_handle, pub_handle, lpattr->exponent)) {
        return 1;
    }
    return 0;
}

/* Find private key (given public key attributes) */
int luna_find_rsa_private_handle(CK_SESSION_HANDLE session_handle, luna_rsa_attributes* lpattr, int flagPrivate, CK_OBJECT_HANDLE_PTR priv_handle_ptr)
{
    CK_OBJECT_CLASS keyclassPublic = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS keyclassPrivate = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keytypeRSA = CKK_RSA;

    CK_RV retCode = CKR_OK;
    CK_USHORT obj_count = 0;
    unsigned ndx = 0;
    CK_OBJECT_HANDLE handles[2];
    CK_ATTRIBUTE attrib[4];
    
    if (flagPrivate) {
		attrib[ndx=0].type = CKA_CLASS;
		attrib[ndx].pValue = (CK_BYTE_PTR)&keyclassPrivate;
		attrib[ndx].ulValueLen = sizeof(keyclassPrivate);  
	} else {
		attrib[ndx=0].type = CKA_CLASS;
		attrib[ndx].pValue = (CK_BYTE_PTR)&keyclassPublic;
		attrib[ndx].ulValueLen = sizeof(keyclassPublic);  
	}

	attrib[ndx=1].type = CKA_KEY_TYPE;
	attrib[ndx].pValue = (CK_BYTE_PTR)&keytypeRSA;
	attrib[ndx].ulValueLen = sizeof(keytypeRSA);  

    attrib[ndx=2].type = CKA_PUBLIC_EXPONENT;
    attrib[ndx].pValue = (CK_BYTE_PTR)lpattr->exponent->pValue;
    attrib[ndx].ulValueLen = lpattr->exponent->ulValueLen;
    
    attrib[ndx=3].type = CKA_MODULUS;
    attrib[ndx].pValue = (CK_BYTE_PTR)lpattr->modulus->pValue;
    attrib[ndx].ulValueLen = lpattr->modulus->ulValueLen;
    
    handles[0] = 0;
    retCode = p11.std->C_FindObjectsInit(session_handle, attrib, 4);
    if (retCode != CKR_OK) {
        fprintf(stderr, "C_FindObjectsInit = 0x%x\n", (int) retCode);
        return 1;
    }
    
    retCode = p11.std->C_FindObjects(session_handle, &handles[0], 2, &obj_count);
    if (retCode != CKR_OK) {
        fprintf(stderr, "C_FindObjects = 0x%x\n", (int) retCode);
        return 1;
    }   

    (*priv_handle_ptr) = handles[0];
    return ((handles[0])&&(obj_count==1)) ? 0 : 1;
    
}

/* Init attribute data */
void luna_rsa_attributes_init(luna_rsa_attributes* lpattr)
{
    memset(lpattr, 0, sizeof(luna_rsa_attributes));
    lpattr->modulus = &lpattr->attr[0];
    lpattr->exponent = &lpattr->attr[1];
}

/* Cleanup attribute data */
void luna_rsa_attributes_fini(luna_rsa_attributes* lpattr)
{
    int i = 0;
    for (i=0; i<2; i++)
    {
        if (lpattr->attr[i].pValue)
        {
            free(lpattr->attr[i].pValue);
        }
    }
    memset(lpattr, 0, sizeof(luna_rsa_attributes));
}

/* Get attribute */
static CK_RV
luna_get_attribute(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE pub_handle, CK_ATTRIBUTE_PTR a_template)
{
    CK_RV retCode = CKR_OK;
    
    /* extract public key, modulus size first */
    a_template[0].pValue = 0;
    a_template[0].ulValueLen = 0;
    retCode = p11.std->C_GetAttributeValue(session_handle, pub_handle, a_template, 1);
    if(retCode != CKR_OK){
        fprintf(stderr, "C_GetAttributeValue(1st) = 0x%x\n", (int) retCode);
        return retCode;
    }
    
    /* allocate enough space to extract attribute */
    a_template[0].pValue = (CK_BYTE_PTR) malloc(a_template[0].ulValueLen+1);
    memset(a_template[0].pValue, 0, a_template[0].ulValueLen+1);
    
    /* extract public key, get modulus */
    retCode = p11.std->C_GetAttributeValue(session_handle, pub_handle, a_template, 1);
    if(retCode != CKR_OK){
        fprintf(stderr, "C_GetAttributeValue(2nd) = 0x%x\n", (int) retCode);
        return retCode;
    }

    return CKR_OK;
}

/* Format string for binary data */
static void fprintf_bin(FILE* fp, void* data, unsigned ndata)
{
   unsigned char* pdata = (unsigned char*)data;
   for ( ; ndata > 0; pdata++, ndata--) {
      fprintf(fp, "%02x", (unsigned)((*pdata)&0x00ff));
   }
}

/* List private keys for selection */
static int luna_select_key(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE* hout, char *szkeytype)
{
    CK_OBJECT_CLASS ulClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ulType = CKK_RSA;

    CK_RV retCode = CKR_OK;
    CK_USHORT obj_count = 0;
    CK_ULONG rcCount = 0;
    char *p_szCkaPublic = NULL;
    
    CK_OBJECT_HANDLE handles[1];
    CK_ATTRIBUTE attrib[2];
    CK_ATTRIBUTE tmpl[1];
    CK_ATTRIBUTE tmpl_modulus[1];
    char buffer[32];
    
    memset(handles, 0, sizeof(handles));
    memset(attrib, 0, sizeof(attrib));
    memset(tmpl, 0, sizeof(tmpl));
    memset(tmpl, 0, sizeof(tmpl));
    memset(tmpl_modulus, 0, sizeof(tmpl_modulus));
    memset(buffer, 0, sizeof(buffer));
    
    hout[0] = 0;

    if (strcmp(szkeytype, "RSA") == 0) {
        /* NOTE: RSA private key has public attributes so... */
        ulClass = CKO_PRIVATE_KEY;
        ulType = CKK_RSA;
    } else if (strcmp(szkeytype, "DSA") == 0) {
        /* NOTE: DSA private key has NO public attributes so... */
        ulClass = CKO_PUBLIC_KEY;
        ulType = CKK_DSA;
    } else if (strcmp(szkeytype, "ECDSA") == 0) {
        /* NOTE: ECDSA private key has NO public attributes so... */
        ulClass = CKO_PUBLIC_KEY;
        ulType = CKK_ECDSA;
    }

    if (1) {
        rcCount = 0;
        attrib[rcCount].type = CKA_CLASS;
        attrib[rcCount].pValue = (CK_BYTE_PTR)&ulClass;
        attrib[rcCount].ulValueLen = sizeof(ulClass);  
        rcCount++;

        attrib[rcCount].type = CKA_KEY_TYPE;
        attrib[rcCount].pValue = (CK_BYTE_PTR)&ulType;
        attrib[rcCount].ulValueLen = sizeof(ulType);  
        rcCount++;
    }

    retCode = p11.std->C_FindObjectsInit(session_handle, attrib, rcCount);
    if (retCode != CKR_OK) {
        fprintf(stderr, "C_FindObjectsInit = 0x%x\n", (int) retCode);
        return 1;
    }
    
        /* List all objects */
	do {
	    obj_count = 0;    
	    handles[0] = 0;
	    retCode = p11.std->C_FindObjects(session_handle, &handles[0], 1, &obj_count);

	    if (retCode != CKR_OK) {
	        fprintf(stderr, "C_FindObjects = 0x%x\n", (int) retCode);
	        return 1;

	    } else if (obj_count==1) {
	    	tmpl[0].type = CKA_LABEL;
	    	tmpl[0].pValue = 0;
	    	tmpl[0].ulValueLen = 0;
	        if (luna_get_attribute(session_handle, handles[0], &tmpl[0])) {
	          fprintf(stderr, "Get Attribute Failed (CKA_LABEL)\n");
	          return 1;
	        }

                /* Get the public key for display */
	    	if (strcmp(szkeytype, "RSA") == 0) {
	    	    p_szCkaPublic = "CKA_MODULUS";
	    	    tmpl_modulus[0].type = CKA_MODULUS;
	    	    tmpl_modulus[0].pValue = 0;
	    	    tmpl_modulus[0].ulValueLen = 0;
	    	} else if (strcmp(szkeytype, "DSA") == 0) {
	    	    p_szCkaPublic = "CKA_VALUE";
	    	    tmpl_modulus[0].type = CKA_VALUE;
	    	    tmpl_modulus[0].pValue = 0;
	    	    tmpl_modulus[0].ulValueLen = 0;
	    	} else if (strcmp(szkeytype, "ECDSA") == 0) {
	    	    p_szCkaPublic = "CKA_EC_POINT";
	    	    tmpl_modulus[0].type = CKA_EC_POINT;
	    	    tmpl_modulus[0].pValue = 0;
	    	    tmpl_modulus[0].ulValueLen = 0;
	    	}

	        if (luna_get_attribute(session_handle, handles[0], &tmpl_modulus[0])) {
	          fprintf(stderr, "Get Attribute Failed (%s)\n", (char*)p_szCkaPublic);
	          return 1;
	        }
	        
	        /* Print handle, label, modulus */
	        if ( (tmpl[0].pValue) && (tmpl_modulus[0].pValue) ) {
  		        fprintf(stdout, "%8u\t\"%s\"\t", (unsigned)handles[0], 
  		            (char*)tmpl[0].pValue);
  		        fprintf_bin(stdout, (void*)tmpl_modulus[0].pValue, (unsigned)tmpl_modulus[0].ulValueLen);
  		        fprintf(stdout, "\n\n");
  		        free(tmpl[0].pValue); tmpl[0].pValue = 0;
  		        free(tmpl_modulus[0].pValue); tmpl_modulus[0].pValue = 0;
	    	}
	        	        
	    }
	} while ( (obj_count > 0) && (retCode == CKR_OK) );
	
    /* Finalize find operation */
    p11.std->C_FindObjectsFinal(session_handle);
    
    /* User selects key handle */
    fprintf(stdout, "\nEnter the key handle : ");
    memset(buffer, 0, sizeof(buffer));
    fgets(buffer, sizeof(buffer), stdin);
    hout[0] = atoi(buffer);

	return 0;
}

/* if we're not logged in here, return an error */
int loggedin( CK_SLOT_ID slotid )
{

   CK_RV retCode;
   CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
   CK_SESSION_HANDLE shandle;

   CK_SESSION_INFO sessInfo;
   memset(&sessInfo, 0, sizeof(sessInfo));

   retCode = p11.std->C_OpenSession(slotid, flags, (CK_BYTE_PTR)"Application", 0, &shandle);
   if(retCode !=CKR_OK) 
   {
      fprintf(stderr, "Open Session Error: Slot number %d. err 0x%x\n", (int) slotid, (int) retCode);
      return 0;
   }

   retCode = p11.std->C_GetSessionInfo( shandle, &sessInfo );
   if(retCode !=CKR_OK) 
   {
      fprintf(stderr, "Get Session Info Error: Slot number %d. err 0x%x\n", (int) slotid, (int) retCode);
      p11.std->C_CloseSession(shandle); shandle = 0;
      return 0;
   }

   if ( sessInfo.state == CKS_RW_USER_FUNCTIONS )
   {
      if (verbose)
         fprintf(stdout, "Confirmed user is logged in.\n" );
      p11.std->C_CloseSession(shandle); shandle = 0;
      /* return 1 because we are logged in */
      return 1;
   }

   p11.std->C_CloseSession(shandle); shandle = 0;
   return 0;
}

/* perform sscanf on string containing format "%02x:%02x:..." */
static unsigned char* parse_hex_bytes(const char* inptr, int separator, unsigned *outsize) 
{ 
   unsigned count = 0, utmp = 0; 
   unsigned char* outptr = NULL; 
   
   /*fprintf(stderr, "inptr = \"%s\" \n", (char*)inptr);*/ 
   if (inptr == NULL) return NULL;
   if (outsize == NULL) return NULL;
    
   outptr = (unsigned char*)malloc(strlen(inptr));
   if (outptr == NULL) return NULL;
 
   for ( ; (inptr != NULL) ; utmp = 256) 
   { 
      if (!isxdigit(inptr[0])) goto goto_fail;
      if (!isxdigit(inptr[1])) goto goto_fail;
      if (! ((inptr[2] == (char)separator) || (inptr[2] == '\0')) ) goto goto_fail;
      if (sscanf(inptr, "%02x", (unsigned*)&utmp) != 1) goto goto_fail;
      if (utmp > 255) goto goto_fail;
      outptr[count++] = (unsigned char)utmp; 
      /*fprintf(stderr, "outptr[count-1] = \"%x\" \n", (unsigned)outptr[count-1]);*/ 
      inptr = strchr(inptr, separator); 
      if (inptr != NULL) inptr++; 
   } 
 
   (*outsize) = count;
   return count ? outptr : NULL;

goto_fail: ;
   if (outptr)
   {
      free(outptr); outptr = NULL;
   }
 
   (*outsize) = 0;
   return NULL;
}


/*
 * Added for sautil v1.0.0-1
 */

/* definitions */
#ifdef OS_WIN32
#define LUNA_CONF_PATH     "c:\\windows"
#define LUNA_FILE_SLASH    "\\"
#define LUNA_CONF_FILE     "crystoki.ini"
#define LUNA_CONF_ENVVAR   "ChrystokiConfigurationPath"
#else
#define LUNA_CONF_PATH     "/etc"
#define LUNA_FILE_SLASH    "/"
#define LUNA_CONF_FILE     "Chrystoki.conf"
#define LUNA_CONF_ENVVAR   "ChrystokiConfigurationPath"
#endif

#define LUNA_MAX_LINE_LEN 1024

/* forward reference */
static char *luna_getprop(const char *confpath, const char *ssection, const char *svalue);

/* Create filename */
static char *luna_filenamedup(char *spath, char *sfile)
{
	char* fn = (char*)malloc(strlen(spath) + 1 + strlen(sfile) + 1 + 8);
	if (fn == NULL) return NULL;
	fn[0] = '\0'; sprintf(fn, "%s%s%s", (char*)spath, (char*)LUNA_FILE_SLASH, (char*)sfile);
	return fn;
}

/* Get path to conf file */
static char *luna_get_conf_path(void)
{
	char* cf = NULL;
	char* envpath = 0;
	
	envpath = getenv(LUNA_CONF_ENVVAR);
	if (envpath != NULL)
	{
		cf = luna_filenamedup(envpath, LUNA_CONF_FILE);
	}
	else
	{
#ifdef OS_WIN32
		fprintf(stderr, "Environment variable is not set: %s.\n", (char*)LUNA_CONF_ENVVAR);
#else
		cf = luna_filenamedup(LUNA_CONF_PATH, LUNA_CONF_FILE);
#endif
	}
	
	return cf;				
}

/* sautil_libname (get library name) */
static char *sautil_libname(void)
{
	const char *ssection = "Chrystoki2";
	char* confpath = NULL;
	char* libname = NULL;

	/* luna_get_conf_path */
	confpath = luna_get_conf_path();
	if (confpath == NULL) { 
		fprintf(stderr, "Failed to get path to config file.\n");
		return NULL;
	}
	
	if (verbose) {
		fprintf(stderr, "Config file: %s.\n", (char*)confpath);
	}
	
#ifdef OS_WIN32
	if (sizeof(void*) > 4) {
		libname = luna_getprop(confpath, ssection, "LibNT64");
	} else {
		libname = luna_getprop(confpath, ssection, "LibNT");
	}
#else /* OS_WIN32 */
	if (sizeof(void*) > 4) {
#if defined( OS_HPUX ) || defined( HPUX ) || defined( __hpux )
		if (libname == NULL) libname = luna_getprop(confpath, ssection, "LibHPUX64");
#endif /* OS_HPUX */
#if defined( OS_AIX ) || defined( AIX ) || defined ( _AIX )
		if (libname == NULL) libname = luna_getprop(confpath, ssection, "LibAIX64");
#endif /* OS_AIX */
		if (libname == NULL) libname = luna_getprop(confpath, ssection, "LibUNIX64"); /* backstop rule */
	} else {
#if defined( OS_HPUX ) || defined( HPUX ) || defined( __hpux )
		if (libname == NULL) libname = luna_getprop(confpath, ssection, "LibHPUX");
#endif /* OS_HPUX */
#if defined( OS_AIX ) || defined( AIX ) || defined ( _AIX )
		if (libname == NULL) libname = luna_getprop(confpath, ssection, "LibAIX");
#endif /* OS_AIX */
		if (libname == NULL) libname = luna_getprop(confpath, ssection, "LibUNIX"); /* backstop rule */
	}
#endif /* OS_WIN32 */

	if (libname == NULL) { 
		fprintf(stderr, "Failed to get path to library file.\n");
		fprintf(stderr, "  See config file: %s.\n", (char*)confpath);
		free(confpath); confpath = NULL;
		return NULL;
	}
	
	free(confpath); confpath = NULL;
	return libname;
}

/* sautil_load (load library) */
static CK_RV sautil_load(void)
{
	char* libname = NULL;
	
	luna_dso = NULL;

	/* sautil_libname */
	libname = sautil_libname();
	if (libname == NULL) { 
		fprintf(stderr, "Library not configured.\n");
		goto err;
	}
	
	/* DSO_load */
	luna_dso = DSO_load(NULL, libname, NULL, 0);
	if (luna_dso == NULL) { 
		fprintf(stderr, "Library not loadable: %s.\n", (char*)libname);
		goto err;
	}
	
	free(libname); libname = NULL;
	return CKR_OK;

err:	
	if (libname != NULL) {
		free(libname); libname = NULL;
	}
	return CKR_GENERAL_ERROR;

}

/* sautil_init (initialize library) */
static CK_RV sautil_init(void)
{
	CK_RV retCode = CKR_OK;
	const char* funcname = NULL;
	
	/* sautil_load */
	if ( (sautil_load()) != CKR_OK ) {
		/*fprintf(stderr, "Library not loadable: %s.\n", (char*)libname);*/
		goto err;
	}

	/* DSO_bind_func */
	p11.C_GetFunctionList = (CK_C_GetFunctionList)DSO_bind_func(luna_dso, (funcname = "C_GetFunctionList"));
	if (p11.C_GetFunctionList == NULL) {
		fprintf(stderr, "Function not found: %s.\n", (char*)funcname);
		goto err;
	}

	p11.ext.CA_SetApplicationID = (CK_CA_SetApplicationID)DSO_bind_func(luna_dso, (funcname = "CA_SetApplicationID"));
	if (p11.ext.CA_SetApplicationID == NULL) {
		fprintf(stderr, "Function not found: %s.\n", (char*)funcname);
		goto err;
	}

	p11.ext.CA_OpenApplicationID = (CK_CA_OpenApplicationID)DSO_bind_func(luna_dso, (funcname = "CA_OpenApplicationID"));
	if (p11.ext.CA_OpenApplicationID == NULL) {
		fprintf(stderr, "Function not found: %s.\n", (char*)funcname);
		goto err;
	}

	p11.ext.CA_CloseApplicationID = (CK_CA_CloseApplicationID)DSO_bind_func(luna_dso, (funcname = "CA_CloseApplicationID"));
	if (p11.ext.CA_CloseApplicationID == NULL) {
		fprintf(stderr, "Function not found: %s.\n", (char*)funcname);
		goto err;
	}

	/* C_GetFunctionList */
	if ( (retCode = p11.C_GetFunctionList(&p11.std)) != CKR_OK ) {
		fprintf(stderr, "C_GetFunctionList error: 0x%x.\n", (int) retCode);
		goto err;
	}

	/* C_Initialize */
	if ( (retCode = p11.std->C_Initialize(NULL_PTR)) != CKR_OK ) {
		fprintf(stderr, "C_Initialize error: 0x%x.\n", (int) retCode);
		goto err;
	}
	
	return CKR_OK;

err:
	return CKR_GENERAL_ERROR;
}

/* sautil_fini (finalize library) */
static void sautil_fini(void)
{
	if (luna_dso == NULL) return;
	
	(void)p11.std->C_Finalize(NULL_PTR);
	DSO_free(luna_dso); luna_dso = NULL;
}

/* sautil_exit (exit application) */
static void sautil_exit(int errcode)
{
	sautil_fini();
	memset(sautil_password, 0, sizeof(sautil_password));
	memset(sautil_szcurve, 0, sizeof(sautil_szcurve));
	exit(errcode);
}

/* Read property value from config file */
static char *luna_getprop(const char *confpath, const char *ssection, const char *svalue)
	{
#ifndef OS_WIN32
	int  rlen = 0;
	unsigned  tmplen = 0;
	char *p = NULL, *e = NULL, *l = NULL;
	char *quote = NULL;
	BIO* cfgbio = NULL;
	char rbuf[LUNA_MAX_LINE_LEN + 1];

	memset(rbuf, 0, sizeof(rbuf));

	if (confpath == NULL)
		{
		return NULL;
		}
	cfgbio = BIO_new_file(confpath, "r");
	if (cfgbio == NULL) 
		{
		return NULL;
		}

	for (;;) 
		{
		if (!(rlen = BIO_gets(cfgbio, rbuf, LUNA_MAX_LINE_LEN))) break; 

		/* find the section string, and, opening brace */
		p = strstr(rbuf, ssection);
		quote = strstr(rbuf, "{");
		if ( (p == NULL) || (strlen(p) == 0) ) continue;
		if ( (quote == NULL) || (strlen(quote) == 0) ) continue;

		/* found the section - let's iterate within section */
		for ( quote=NULL ; (quote==NULL) ; ) 
			{
			if (!(rlen = BIO_gets(cfgbio, rbuf, LUNA_MAX_LINE_LEN))) break; 

			/* check for closing brace */
			quote = strstr(rbuf, "}");

			/* find the value string; beware of substrings; e.g., LibPath and LibPath64 */ 
			tmplen = strlen(svalue);
			p = strstr(rbuf, svalue); 
			if ( (p == NULL) || (strlen(p) <= tmplen) ) continue; 
			if ( (isalnum(p[tmplen])) || (p[tmplen] == '_') ) continue; 

			/* find and skip past = */
			p = strchr(p, '=');
			if ( (p == NULL) || (strlen(p) == 0) ) continue;

			/* skip past = and eat all white space */
			while (isspace(*(++p)));

			/* find terminating ; and replace with null */
			if ( (e = strchr(p, ';')) == NULL ) continue;
			(*e) = 0;

			/* found the data - let's break */
			l = BUF_strdup(p);
			break;
			}
		break; /* Break since we already encountered the section name */
		}
	/* Close file handle */
	BIO_free(cfgbio);
	return l;

#else /* OS_WIN32 */
	const char *pbError = "##ERROR##";
	DWORD dwrc = 0;
	char rbuf[LUNA_MAX_LINE_LEN + 1];

	memset(rbuf, 0, sizeof(rbuf));
	dwrc = GetPrivateProfileString(
		ssection,
		svalue,
		pbError,
		rbuf,
		LUNA_MAX_LINE_LEN,
		(char*)confpath);

	if ( (dwrc < 1) || (strcmp(rbuf, pbError) == 0) )
		{
		return NULL;
		}
		
	return BUF_strdup(rbuf);
#endif /* OS_WIN32 */
	}


/* sautil_gets_password (prompt for password; no echo) */
static int sautil_gets_password(char *secretString, unsigned maxlen)
{
    char *secretString0 = secretString;
    unsigned ii=0;
    unsigned len=0; /* running total length of string */
    char c=0; /* character read in from user */
#ifdef OS_WIN32
    DWORD mode=0;
#endif
    
    fflush(stdout);
    fflush(stderr);
    
#ifdef OS_WIN32
    /* This console mode stuff only applies to windows. */
    if (GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode)) {
        if (SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode & (!ENABLE_ECHO_INPUT))) {
            
            while (c  != '\r') {
                /* wait for a character to be hit */
                while (!_kbhit()) {
                    Sleep(100);
                }
                /* get it */
                c = _getch();
                
                /* check for carriage return */
                if (c != '\r') {
                    /* check for backspace */
                    if (c!='\b') {
                        /* neither CR nor BS -- add it to the password string */
                        printf("*");
                        *secretString++ = c;
                        len++;
                    } else {
                        /* handle backspace -- delete the last character & erase it from the screen */
                        if (len > 0) {
                            secretString--;
                            len--;
                            printf("\b \b");
                        }
                    }
                }
            }
            /* Add the zero-termination */
            (*secretString) = '\0';
            
            SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
        }
    }
    
#else /* OS_WIN32 */

    {
    struct termios tio;
    int fd;
    int rc;
    cc_t old_min, old_time;
    char termbuff[200];
    
    /* flush prompt string before reading input */
    fflush( stdout );
    
    fd = open( ctermid( termbuff ), O_RDONLY );
    if (fd == -1) 
    {
        return -1;
    }
    
    rc = tcgetattr( fd, &tio );
    if (rc == -1) 
    {
        close(fd);
        return -1;
    }
    
    /* turn off canonical mode & echo */
    old_min = tio.c_cc[VMIN];
    old_time = tio.c_cc[VTIME];
    tio.c_lflag = tio.c_lflag & ~ICANON & ~ECHO;
    tio.c_cc[VMIN]=1;
    tio.c_cc[VTIME]=0;
    
    rc = tcsetattr( fd, TCSADRAIN, &tio );
    if ( rc == -1 ) 
    {
        close( fd );
        return -1;
    }
    
    /* continue to loop until we get the 'enter' */
    while ( c!='\n' ) 
    {
        /* read in the next char */
        rc = read( fd, &c, 1 );
        if ( rc != 0 ) 
        {
            if ( c != '\n' ) 
            {
                /* check for backspace ( and ASCII 127 which is BS in linux) */
                if ( ( c!='\b' ) && ( (int)c!=127) )
                {
                    /* neither CR nor BS -- add it to the password string */
                    fprintf( stdout, "*" );
                    fflush( stdout );
                    *secretString++ = c;
                    len++;
                } 
                else 
                {
                    /* handle backspace -- delete the last character & erase it from the screen */
                    if ( len > 0 ) 
                    {
                        secretString--;
                        len--;
                        fprintf( stdout, "\b \b" );
                        fflush( stdout );
                    }
                }
            }
        } 
        else 
        {
            /* we're having problems getting the character */
            close( fd );
            return -1;
        }
    } /* while */
    
    *secretString++ = '\0';
    
    /* return terminal to its original state */
    tio.c_lflag = tio.c_lflag | ICANON | ECHO;
    tio.c_cc[VMIN] = old_min;
    tio.c_cc[VTIME] = old_time;
    
    rc = tcsetattr(fd, TCSADRAIN, &tio);
    if ( rc == -1 ) 
    {
        close( fd );
        return -1;
    }
    
    close( fd );
    }
#endif /* OS_WIN32 */

    /* obscure password length */
    for (ii = len; ii < maxlen; ii++)
    {
        fprintf( stdout, "*" );
    }
    fprintf( stdout, "\n" );
    
    /* if we didn't get a string, return false */
    if ( (len > maxlen) || (len < 4) || (len != strlen(secretString0)) )
    {
        return -1;
    }
    
    return len;
    
}

/* string print (unique CKA_LABEL) */
static void
sautil_sprint_unique(char *szPubLabel, char *szPrivLabel, 
	const char *szKeytype, unsigned uKeysize)
{
  struct tm *p_tmNow = NULL;
  time_t timeNow;
  char szUnique[CA3UTIL_MAX_STRING+1];
  
  memset(&timeNow, 0, sizeof(timeNow));
  memset(szUnique, 0, sizeof(szUnique));
  
  LOCAL_SLEEP(1); /* sleep so that each key has a unique timestamp */
  timeNow = time(NULL);
  p_tmNow = localtime(&timeNow);
  sprintf(szUnique, "%04u.%02u.%02u.%02u.%02u.%02u",
    (unsigned)(p_tmNow->tm_year + 1900),
    (unsigned)p_tmNow->tm_mon,
    (unsigned)p_tmNow->tm_mday,
    (unsigned)p_tmNow->tm_hour,
    (unsigned)p_tmNow->tm_min,
    (unsigned)p_tmNow->tm_sec
    );

  if (uKeysize > 0)
  {
    (void)sprintf(szPubLabel,  "%s %u Public - %s",  
      (char*)szKeytype, (unsigned)uKeysize, (char*)szUnique);
    (void)sprintf(szPrivLabel, "%s %u Private - %s", 
      (char*)szKeytype, (unsigned)uKeysize, (char*)szUnique);
  }
  else
  {
    (void)sprintf(szPubLabel,  "%s Public - %s",  
      (char*)szKeytype, (char*)szUnique);
    (void)sprintf(szPrivLabel, "%s Private - %s", 
      (char*)szKeytype, (char*)szUnique);
  }
}

/* compute sha1(prng_bytes); i.e., compute temporary CKA_ID */
static CK_RV
sautil_sha1_prng(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR baSha1)
{
  unsigned char foobytes[512];
  if (p11.std->C_GenerateRandom(session_handle, foobytes, sizeof(foobytes)) != CKR_OK) {
    return CKR_GENERAL_ERROR;
  }
  (void)SHA1(foobytes, sizeof(foobytes), baSha1);
  return CKR_OK;
}

/* duplicate memory */
static CK_VOID_PTR
sautil_memdup(
  CK_VOID_PTR pValue,  /* can be null */
  CK_ULONG ulValueLen)
{
  CK_VOID_PTR ptr = NULL;
  if (ulValueLen < 1) return NULL;
  ptr = malloc(ulValueLen);
  if (ptr != NULL) {
    memset(ptr, 0, ulValueLen);
    if (pValue != NULL) {
      memcpy(ptr, pValue, ulValueLen);
    }    
  }
  return ptr;
}

/* replace one item in table of CK_ATTRIBUTE */
static void sautil_ckatab_malloc_replace(CK_ATTRIBUTE *tab, CK_ULONG tabsize,
  CK_ATTRIBUTE_TYPE type,
  CK_BYTE_PTR pValue, /* can be null */
  CK_ULONG ulValueLen)
{
  CK_ULONG ii = 0;
  if (ulValueLen < 1) return;
  for (ii = 0; ii < tabsize; ii++) {
    if (tab[ii].type == type) {
      tab[ii].pValue = sautil_memdup(pValue, ulValueLen);
      tab[ii].ulValueLen = ulValueLen;
      return;
    }
  }
  
  /* a coding error if we get this far */
  fprintf(stderr, "BUG: attribute type not found: 0x%x.\n", (unsigned)type);
  sautil_exit(-1);
}

/* free table of CK_ATTRIBUTE */
static void sautil_ckatab_free_all(CK_ATTRIBUTE *tab, CK_ULONG tabsize)
{
  CK_ULONG ii = 0;
  for (ii = 0; ii < tabsize; ii++) {
    if (tab[ii].pValue != NULL) {
      free(tab[ii].pValue); tab[ii].pValue = NULL;
    }
    tab[ii].ulValueLen = 0;
  }
}

/* fill table of CK_ATTRIBUTE */
static CK_RV sautil_ckatab_malloc_object(
  CK_ATTRIBUTE *tab, CK_ULONG tabsize,
  CK_OBJECT_HANDLE hObject,
  CK_SESSION_HANDLE hSession)
{
  CK_RV retCode = ~0;
  CK_ULONG ii = 0;
  CK_ULONG jj = 0;
  
  /* NOTE: get one attribute at a time in case P11 lib has related issue! */
  for (ii = 0; ii < tabsize; ii++) {
    retCode = luna_get_attribute(hSession, hObject, &tab[ii]);
    if (retCode != CKR_OK) {
      for (jj = 0; jj < ii; jj++) {
        free(tab[jj].pValue); tab[jj].pValue = NULL;
      }
      return retCode;
    }
  }
  
  return retCode;
}


#if defined(LUNA_OSSL_ECDSA)
/* ECDSA */

/* initialize ecdsa key templates */
static int
init_ecdsa_key_template(CK_ATTRIBUTE **pubTemp, 
  CK_USHORT *pubTempSize, 
  CK_ATTRIBUTE **privTemp, 
  CK_USHORT *privTempSize,
  CK_BYTE *pub_key_label, 
  CK_BYTE *priv_key_label,
  const char *curve_name,
  EC_GROUP *group,
  CK_BYTE_PTR baCkId, CK_ULONG baCkIdLen)
{
  CK_BBOOL bTrue = TRUE, bFalse = FALSE;
  CK_ATTRIBUTE *pubTemplate = NULL;
  CK_ATTRIBUTE *privTemplate = NULL;
  CK_ULONG ii = 0;

  CK_ULONG curve_len = 0;
  CK_BYTE curve_data[SAUTIL_EC_CURVE_MAX_BYTES];
  
  CK_ATTRIBUTE pub_template[] =
  {
    {CKA_TOKEN,    0, 0},
    {CKA_PRIVATE,  0, 0},
    {CKA_VERIFY,   0, 0},
    {CKA_ECDSA_PARAMS,   0, 0},
    {CKA_ID,       0, 0},
    {CKA_LABEL,    0, 0},
  };

  CK_ATTRIBUTE priv_template[] =
  {
    {CKA_TOKEN,     0, 0},
    {CKA_PRIVATE,   0, 0},
    {CKA_SENSITIVE, 0, 0},
    {CKA_SIGN,      0, 0},
    {CKA_ID,        0, 0},
    {CKA_LABEL,     0, 0},
  };

  /* select curve */
  if (group == NULL) {
    CK_ULONG uCurve = ~0;
    
    for (ii = 0; ii < LUNA_DIM(sautil_curves); ii++) {
      if (strcmp(curve_name, sautil_curves[ii].name) == 0) {
        uCurve = ii;
        break;
      }
    }

    if (uCurve >= LUNA_DIM(sautil_curves)) {
      fprintf(stderr, "Unrecognized curve name [%s]\n", (char*)curve_name);
      return -1;
    }
    
    curve_len = sautil_curves[uCurve].ulValueLen;
    if (curve_len > sizeof(curve_data)) {
      fprintf(stderr, "Buffer too small [curve_len=%u]\n", (unsigned)curve_len);
      return -1;
    }
    memcpy(curve_data, sautil_curves[uCurve].pValue, curve_len);
  
    if (verbose) {
      fprintf(stdout, "EC_CURVE_NAME=%s\n", (char*)curve_name);
      fprintf(stdout, "EC_CURVE_COMMENT=%s\n", (char*)"SAUTIL BUILTIN CURVE");
    }
    
  } else {
	EC_builtin_curve *curves = NULL;
	size_t crv_len = 0;
	size_t n = 0;
	int nid = 0;

        if (!EC_GROUP_check(group, NULL))
        	{
		fprintf(stderr, "EC_GROUP_check failed. \n");
		return -1;
        	}
        	
        if ( (nid = EC_GROUP_get_curve_name(group)) < 1 )
        	{
		fprintf(stderr, "EC_GROUP_get_curve_name failed. \n");
		return -1;
        	}

	crv_len = EC_get_builtin_curves(NULL, 0);
	curves = OPENSSL_malloc((int)(sizeof(EC_builtin_curve) * crv_len));
	if (curves == NULL)
		{
		fprintf(stderr, "OPENSSL_malloc failed. \n");
		return -1;
		}

	if (!EC_get_builtin_curves(curves, crv_len))
		{
		fprintf(stderr, "EC_get_builtin_curves failed. \n");
		OPENSSL_free(curves); curves = NULL;
		return -1;
		}
	
	for (n = 0; n < crv_len; n++)
		{
		const char *comment = NULL;
		const char *sname = NULL;
		ASN1_OBJECT *asnobj = NULL;
		
		if (curves[n].nid == nid) /* match */
			{
			comment = curves[n].comment;
			if (comment == NULL)
				{
				comment = "OPENSSL BUILTIN CURVE";
				}
				
			sname = OBJ_nid2sn(curves[n].nid);
			if (sname == NULL)
				{
				sname = "(NULL)";
				}

			if (verbose)
				{
				fprintf(stdout, "EC_CURVE_NAME=%s\n", (char*)sname);
				fprintf(stdout, "EC_CURVE_COMMENT=%s\n", (char*)comment);
				}

			asnobj = OBJ_nid2obj(curves[n].nid);
			if (asnobj == NULL)
				{
				fprintf(stderr, "OBJ_nid2obj failed. \n");
				OPENSSL_free(curves); curves = NULL;
				return -1;
				}

			curve_len = (asnobj->length + 2);
			if (curve_len > sizeof(curve_data))
				{
				fprintf(stderr, "Buffer too small [curve_len=%u]. \n", (unsigned)curve_len);
				OPENSSL_free(curves); curves = NULL;
				return -1;
				}
				
			curve_data[0] = 0x06;
			curve_data[1] = asnobj->length;
			memcpy(&curve_data[2], asnobj->data, asnobj->length);
			break;
			} /* match */
		} /* for loop */

	if (n >= crv_len)
		{
		fprintf(stderr, "Curve does not match any builtin curves. \n");
		OPENSSL_free(curves); curves = NULL;
		return -1;
		}
		
	OPENSSL_free(curves); curves = NULL;
  }
  
  /* set cka value */
  sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_TOKEN, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_PRIVATE, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_VERIFY, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_ECDSA_PARAMS, curve_data, curve_len);
  sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_ID, baCkId, baCkIdLen);
  sautil_ckatab_malloc_replace(pub_template, LUNA_DIM(pub_template), CKA_LABEL, pub_key_label, (CK_ULONG)strlen((char*)pub_key_label));
  
  sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_TOKEN, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_PRIVATE, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_SENSITIVE, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_SIGN, &bTrue, sizeof(bTrue));
  sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_ID, baCkId, baCkIdLen);
  sautil_ckatab_malloc_replace(priv_template, LUNA_DIM(priv_template), CKA_LABEL, priv_key_label, (CK_ULONG)strlen((char*)priv_key_label));

  /* return public template */
  pubTemplate = (CK_ATTRIBUTE*)malloc(sizeof(pub_template));
  memcpy(pubTemplate, pub_template, sizeof(pub_template));
  (*pubTemp) = pubTemplate;
  (*pubTempSize) = LUNA_DIM(pub_template);

  /* return private template */
  privTemplate = (CK_ATTRIBUTE*)malloc(sizeof(priv_template));
  memcpy(privTemplate, priv_template, sizeof(priv_template));
  (*privTemp) = privTemplate;
  (*privTempSize) = LUNA_DIM(priv_template);

  return 0;
}

/* generate new ecdsa keypair */
static int
op_generate_ecdsa_key_pair(CK_SLOT_ID slotid, CK_USHORT modulussize, 
  char *keypair_fname, char *param_fname)
{
  int ret = -1;
  CK_RV retCode = ~0;
  CK_ATTRIBUTE *pub_template = NULL;
  CK_ATTRIBUTE *priv_template = NULL;
  CK_USHORT pub_template_size = 0;
  CK_USHORT priv_template_size = 0;
  CK_OBJECT_HANDLE pub_handle = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE priv_handle = CK_INVALID_HANDLE;
  CK_SESSION_HANDLE session_handle = CK_INVALID_HANDLE;
  CK_BYTE *pubLabel = NULL;
  CK_BYTE *privLabel = NULL;
  EC_GROUP *group = NULL;
  
  CK_MECHANISM key_gen_mech = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
  
  char szPubLabel[CA3UTIL_MAX_STRING+1];
  char szPrivLabel[CA3UTIL_MAX_STRING+1];
  CK_BYTE baCkId[20];

  memset(szPubLabel, 0, sizeof(szPubLabel));
  memset(szPrivLabel, 0, sizeof(szPrivLabel));
  memset(baCkId, 0, sizeof(baCkId));

  ret = set_application_id(app_id_hi, app_id_lo);
  if (ret != 0)
    return -1;
 
  group = NULL;
  if (param_fname != NULL) {
	/* get p, q, g from file */
	BIO *f = NULL;
    
	if ( (f = BIO_new(BIO_s_file())) == NULL )
		{
		fprintf(stderr, "BIO_new failed. \n");
		return -1;
		}
	
	if (BIO_read_filename(f, param_fname) <= 0)
		{
		fprintf(stderr, "BIO_read_filename failed. \n");
		return -1;
		}

	if ( (group = PEM_read_bio_ECPKParameters(f, NULL, NULL, NULL)) == NULL )
		{
		fprintf(stderr, "PEM_read_bio_ECPKParameters failed. \n");
		return -1;
		}
  }
  
  switch (modulussize) {
    case 1024:
      sautil_sprint_unique(szPubLabel, szPrivLabel, "ECDSA", 0);
      pubLabel  = (CK_BYTE *)szPubLabel;
      privLabel = (CK_BYTE *)szPrivLabel;
      break;
    default:
      fprintf(stderr, "BUG: coding error. \n");
      return -1;
  }

  if (open_session(slotid, &session_handle) != 0)
     return -1;
  
  /* if we're not logged in here, return an error */
  if (!loggedin( slotid )) {
     fprintf( stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int) slotid );
     return -1;
  }

  /* generate temporary CKA_ID */
  if (sautil_sha1_prng(session_handle, baCkId) != CKR_OK) {
     fprintf(stderr, "Failed RNG.\n");
     return -1;
  }

  ret = init_ecdsa_key_template(&pub_template, &pub_template_size, 
    &priv_template, &priv_template_size, 
    pubLabel, 
    privLabel,
    sautil_szcurve, group,
    baCkId, sizeof(baCkId));
  if (ret != 0)
    return -1;

  /* C_GenerateKeyPair */
  if (verbose) 
    fprintf(stdout, "Generating ECDSA key pair.\n");
  
  retCode = p11.std->C_GenerateKeyPair(session_handle, 
    &key_gen_mech,
    pub_template, pub_template_size,
    priv_template, priv_template_size,
    &pub_handle, 
    &priv_handle);
  if ( (retCode != CKR_OK) 
    || (pub_handle == CK_INVALID_HANDLE)
    || (priv_handle == CK_INVALID_HANDLE) ) {
    fprintf(stderr, "Generate ECDSA Key Pair Error 0x%x.\n", (int) retCode);
    goto err;
  }

  if (verbose) { 
    fprintf(stdout, "ECDSA Public key handle is %u\n", (unsigned) pub_handle);
    fprintf(stdout, "ECDSA Private key handle is %u\n", (unsigned) priv_handle);
  }

  /* FIXME: CKA_ID should be derived from public key */
  if (verbose) { 
    luna_dump_hex(stdout, "CKA_ID=", baCkId, sizeof(baCkId));
  }

  ret = write_pem_ecdsa_key_pair(session_handle, pub_handle, priv_handle, keypair_fname);
  if (ret != 0)
    goto err;

  sautil_ckatab_free_all(pub_template, pub_template_size);
  sautil_ckatab_free_all(priv_template, priv_template_size);
  return 0;
  
err:
  sautil_ckatab_free_all(pub_template, pub_template_size);
  sautil_ckatab_free_all(priv_template, priv_template_size);
  close_session(session_handle); session_handle = 0;
  return -1;
}

/* write ecdsa key to file */
static int
write_pem_ecdsa_key_pair(CK_SESSION_HANDLE session_handle, 
  CK_OBJECT_HANDLE pub_handle, 
  CK_OBJECT_HANDLE priv_handle_UNUSED, 
  char *keypair_fname)
{
  int ret = -1;
  CK_RV retCode = ~0;
  BIO *outfile = NULL;
  EC_KEY *dsa = NULL;
  CK_ULONG ii = 0;
  CK_ULONG jj = 0;
  const unsigned ndxP = 0;
  const unsigned ndxQ = 1;
  const unsigned ndxId = 2;

  CK_ATTRIBUTE ckaPublic[] = { 
  	{ CKA_EC_PARAMS, NULL_PTR, 0 },
  	{ CKA_EC_POINT, NULL_PTR, 0 },
  	{ CKA_ID, NULL_PTR, 0 }
  };
  
  CK_ATTRIBUTE attrP;
  CK_ATTRIBUTE attrQ;

  /* open file for writing (before hsm io) */ 
  if ((outfile = BIO_new(BIO_s_file())) == NULL) {
    fprintf(stderr, "Cannot open output file.\n");
    goto err;
  }

  if (BIO_write_filename(outfile, keypair_fname) <= 0) {
    fprintf(stderr, "Cannot open file for writing: %s.\n", (char*)keypair_fname);
    goto err;
  }

  /* extract public key value length */
  retCode = sautil_ckatab_malloc_object(
    ckaPublic, LUNA_DIM(ckaPublic),
    pub_handle,
    session_handle);
  if ( (retCode != CKR_OK) 
    || (ckaPublic[ndxP].pValue == NULL) 
    || (ckaPublic[ndxQ].pValue == NULL) 
    || (ckaPublic[ndxId].pValue == NULL) 
    || (ckaPublic[ndxP].ulValueLen < SAUTIL_EC_CURVE_MIN_BYTES)
    || (ckaPublic[ndxQ].ulValueLen < 2)
    || (ckaPublic[ndxId].ulValueLen < 20)
    ) {
    fprintf(stderr, "Failed to extract public ECDSA key: 0x%x\n", (int) retCode);
    goto err;
  }

  if (verbose) {
    luna_dump_hex(stdout, "CKA_EC_POINT=", ckaPublic[1].pValue, ckaPublic[1].ulValueLen);
  }

  attrP = ckaPublic[ndxP];
  attrQ = ckaPublic[ndxQ];
  
	/********/
	/* if ((dsa = EC_KEY_new_method(eng)) == NULL) goto err; */
	if ((dsa = EC_KEY_new()) == NULL) goto err;
	if ((dsa->priv_key = BN_new()) == NULL) goto err;
	/* set private key to 1 */
	if (!BN_one(dsa->priv_key)) goto err;
	/* set group */
	if (1)
		{
		CK_BYTE_PTR buf_ptr = NULL;
		CK_ULONG buf_len = 0;
		const unsigned char **in = NULL;
		
		buf_ptr = (CK_BYTE_PTR)attrP.pValue; 
		buf_len = attrP.ulValueLen;
		in = (const unsigned char **) &buf_ptr;
		if (d2i_ECParameters(&dsa, in, buf_len) == NULL)
			{
			LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
			ERR_add_error_data(1, "d2i_ECParameters");
			goto err;
			}
			
		if (!EC_GROUP_check(dsa->group, NULL))
			{
			LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
			ERR_add_error_data(1, "EC_GROUP_check");
			goto err;
			}
		}
	/* set public key */
	if (1)
		{
		CK_BYTE_PTR buf_ptr = NULL;
		CK_ULONG buf_len = 0;
		const unsigned char **in = NULL;
		
		point_conversion_form_t form = 0;
		unsigned size2 = 0;
		size_t field_len = 0;
		size_t enc_len = 0;
		
		buf_ptr = (CK_BYTE_PTR)attrQ.pValue; 
		buf_len = attrQ.ulValueLen;
		form = (point_conversion_form_t) (*buf_ptr);
		if (form != POINT_CONVERSION_UNCOMPRESSED)
			{
			LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
			ERR_add_error_data(1, "form != POINT_CONVERSION_UNCOMPRESSED");
			goto err;
			}
			
		size2 = (unsigned) (*(buf_ptr + 1));
		buf_ptr += 2; buf_len -= 2;
		field_len = BN_num_bytes(&dsa->group->field);
		enc_len = (1 + 2*field_len);
		
		for (; (buf_len > 2) && ((*buf_ptr) == 0) & (size2 < enc_len);)
			{
			buf_ptr += 2; buf_len -= 2; size2 += 2;
			}
		
		in = (const unsigned char **) &buf_ptr;
		if (!o2i_ECPublicKey(&dsa, in, buf_len))
			{
			LUNACA3err(LUNACA3_F_LOADKEY, LUNACA3_R_EGETATTR);
			ERR_add_error_data(1, "o2i_ECPublicKey");
			goto err;
			}
		}
	/********/
	
	/* Write keyfile */
	/* NOTE: we know EC_KEY_check_key fails because private key is pseudo */
	if (!PEM_write_bio_ECPrivateKey(outfile, dsa, NULL, NULL, 0, NULL, NULL))
		{
		fprintf(stderr, "PEM_write_bio_ECPrivateKey failed.\n");
		goto err;
		}

	ret = 0;
	if (verbose) fprintf(stdout, "Wrote file \"%s\".\n", (char*)keypair_fname);

err:
	if (dsa != NULL)
		{
		EC_KEY_free(dsa); dsa = NULL;
		}

	sautil_ckatab_free_all(ckaPublic, LUNA_DIM(ckaPublic));
	if (ret != 0) print_errors_and_exit();
	return ret;
}


/* delete ecdsa keypair */
static int
op_delete_ecdsa_key_pair(CK_SLOT_ID slotid, char *keypair_fname)
{
  BIO *f = NULL;
  int ret = -1;
  EC_KEY *dsa = NULL;
  CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
  CK_SESSION_HANDLE session_handle = 0;
  CK_RV retCode = CKR_GENERAL_ERROR;
  luna_context_t ctx = LUNA_CONTEXT_T_INIT;
   
 /* open file before hsm io */
 if ((f = BIO_new(BIO_s_file())) == NULL) {
   fprintf(stderr, "Cannot open file.\n");
   goto err;
 }

 if (BIO_read_filename(f, keypair_fname) <= 0) {
   fprintf(stderr, "Cannot open [%s] for reading.\n", keypair_fname);
   goto err;
 }

 if (!(dsa = PEM_read_bio_ECPrivateKey(f, NULL, NULL, NULL))) {
   fprintf(stderr, "Failed reading ECDSA key pair. file: [%s]\n", keypair_fname);
   goto err;
 }
 
 if (set_application_id(app_id_hi, app_id_lo) != 0)
   goto err;
 if (open_session(slotid, &session_handle) != 0)
   goto err;

  /* if we're not logged in here, return an error */
  if ( !loggedin( slotid ) ) {
     fprintf( stderr, "Error: The user is not logged in to the selected slot (%d).\n", (int) slotid );
     goto err;
  }

  /* fill luna_context_t */
  ctx.hSession = session_handle;
  ctx.flagInit = 1;

 /* ALWAYS Destroy private object first, if the public dsa key is erased first
  * then we wont be able to find the private one */
  handle = luna_find_ecdsa_handle(&ctx, dsa, 1);
  if ( (handle == CK_INVALID_HANDLE)
    || ((retCode = p11.std->C_DestroyObject(session_handle, handle)) != CKR_OK) ) {
    fprintf(stderr, "Delete private failed.\n");
    goto err;
  }
 
  if (verbose) { 
    fprintf(stdout, "ECDSA private key handle is %u\n", (unsigned) handle);
  }
 
  fprintf(stderr, "Delete private ok.\n");

  /* Destroy public object */
  handle = luna_find_ecdsa_handle(&ctx, dsa, 0);
  if ( (handle == CK_INVALID_HANDLE)
    || ((retCode = p11.std->C_DestroyObject(session_handle, handle)) != CKR_OK) ) {
    fprintf(stderr, "Delete public failed.\n");
    goto err;
  }
 
  if (verbose) { 
    fprintf(stdout, "ECDSA public key handle is %u\n", (unsigned) handle);
  }
 
  fprintf(stderr, "Delete public ok.\n");

  ret = 0;
 
err:
  if (dsa) EC_KEY_free(dsa);
  BIO_free(f); 
 
  return ret;
}

/* Code adapted from SafeNet's engine "e_lunaca3.c" uses OpenSSL indentation. */ 

#define LUNA_INVALID_HANDLE  CK_INVALID_HANDLE
#define LUNA_malloc  malloc
#define LUNA_free  free

#define LUNA_MEMCMP_MIN_LEN  (14)
#define LUNA_MEMCMP_MAX_DIFF  (4)

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME  "luna_attribute_malloc"

/* Get attribute value */
static int luna_attribute_malloc(luna_context_t *ctx, CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_PTR pAttr)
	{
	CK_RV retCode = 0;

	pAttr->ulValueLen = 0;	
	pAttr->pValue = 0;	
	retCode = p11.std->C_GetAttributeValue(ctx->hSession, handle, pAttr, 1);
	if (retCode != CKR_OK)
		{
		fprintf(stderr, LUNA_FUNC_NAME": C_GetAttributeValue.\n");
		goto err;
		}
	/* NOTE: assert length is non-zero; esp. for CKA_ID */
	if (pAttr->ulValueLen < 1)
		{
		fprintf(stderr, LUNA_FUNC_NAME": ulValueLen < 1.\n");
		goto err;
		}
	/* NOTE: always allocated on heap */
	pAttr->pValue = (CK_BYTE_PTR)LUNA_malloc(pAttr->ulValueLen);
	retCode = p11.std->C_GetAttributeValue(ctx->hSession, handle, pAttr, 1);
	if (retCode != CKR_OK)
		{
		fprintf(stderr, LUNA_FUNC_NAME": C_GetAttributeValue.\n");
		goto err;
		}
	return 1;	
err:
	if (pAttr->pValue != NULL) LUNA_free(pAttr->pValue);
	pAttr->ulValueLen = 0;
	pAttr->pValue = 0;
	return 0;
	}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME  "luna_attribute_free"

/* helper function (free data for attribute) */
static void luna_attribute_free(CK_ATTRIBUTE_PTR p_attr)
	{
	unsigned ii = 0;

	for (ii = 0; ii < 1; ii++)
		{
		if (p_attr[ii].pValue != NULL)
			{
			LUNA_free(p_attr[ii].pValue);
			p_attr[ii].pValue = NULL;
			p_attr[ii].ulValueLen = 0;
			}
		}
		
	/* NOTE: dont zeroize p_attr because that wipes out the "type" field too! */
	}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME  "luna_find_object_ex1"

/* Find object */
static int luna_find_object_ex1(luna_context_t *ctx, 
	CK_ATTRIBUTE_PTR pAttr, CK_ULONG nAttr, 
	CK_OBJECT_HANDLE_PTR pHandle, 
	int flagCountMustEqualOne)
	{
	CK_RV retCode = 0;
	CK_OBJECT_HANDLE arrayHandle[2] = { LUNA_INVALID_HANDLE, LUNA_INVALID_HANDLE };
	CK_ULONG nObjFound = 0;

	retCode = p11.std->C_FindObjectsInit(ctx->hSession, pAttr, nAttr);
	if (retCode != CKR_OK)
		{
		fprintf(stderr, LUNA_FUNC_NAME": C_FindObjectsInit=0x%x.\n", (unsigned)retCode);
		goto err;
		}

	if (flagCountMustEqualOne)
		{
		retCode = p11.std->C_FindObjects(ctx->hSession, arrayHandle, LUNA_DIM(arrayHandle), &nObjFound);
		}
	else
		{
		retCode = p11.std->C_FindObjects(ctx->hSession, arrayHandle, 1, &nObjFound); /* possible optimization */
		}
	if (retCode != CKR_OK)
		{
		fprintf(stderr, LUNA_FUNC_NAME": C_FindObjects=0x%x.\n", (unsigned)retCode);
		goto err;
		}

	(void)p11.std->C_FindObjectsFinal(ctx->hSession);
	if (nObjFound < 1) goto err;
	if (arrayHandle[0] == LUNA_INVALID_HANDLE) goto err;
	if ( flagCountMustEqualOne && (nObjFound != 1) )
		{
		fprintf(stderr, LUNA_FUNC_NAME": nObjFound=0x%x.\n", (unsigned)nObjFound);
		goto err;
		}
	(*pHandle) = arrayHandle[0];
	return 1;
	
err:
	(*pHandle) = 0;
	return 0;
	}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME  "luna_memcmp_rev_inexact"

/* Compare memory (reverse order, inexact) */
static CK_ULONG luna_memcmp_rev_inexact(
	CK_BYTE_PTR base_p, CK_ULONG base_len,
	CK_BYTE_PTR token_p, CK_ULONG token_len)
	{
	CK_ULONG max_count = 0;
	CK_ULONG diff_count = 0;
	CK_ULONG ii = 0;
	
	max_count = LUNA_MIN(base_len, token_len);
	if (max_count < LUNA_MEMCMP_MIN_LEN) return -1; /* not enough bytes to compare */

	diff_count = LUNA_DIFF(base_len, token_len);
	if (diff_count > LUNA_MEMCMP_MAX_DIFF) return -2; /* the sizes are not close enough */

	for (ii = 0; ii < max_count; ii++)
		{
		/* compare in reverse order */
		if (token_p[token_len - ii - 1] != base_p[base_len - ii - 1]) break;
		}

	/* ii = number of bytes that matched */
	diff_count = LUNA_DIFF(ii, base_len);
	if (diff_count > LUNA_MEMCMP_MAX_DIFF) return -3; /* not enough matching bytes */
	
	/* TODO: we should check the value of the ignored bytes (e.g., asn1 header stuff) */
	
	return 0; /* success */
	}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME  "luna_find_object_inexact"

/* Find object; must be unique; use inexact algorithm */
static int luna_find_object_inexact(luna_context_t *ctx, 
	CK_ATTRIBUTE_PTR pAttr, CK_ULONG nAttr, 
	CK_OBJECT_HANDLE_PTR pHandle, 
	CK_ATTRIBUTE_PTR attrBase)
	{
	int have_init = 0;
	CK_RV retCodeTotal = CKR_OK;
	CK_RV retLoop = CKR_OK;
	CK_RV retCode = CKR_OK;
	CK_ULONG obj_count = 0;
	CK_ULONG match_count = 0;
	CK_OBJECT_HANDLE match_handle = LUNA_INVALID_HANDLE;

	CK_ATTRIBUTE attrFoo[1];
	CK_OBJECT_HANDLE handles[1] = { LUNA_INVALID_HANDLE };

	memset(attrFoo, 0, sizeof(attrFoo));

	if ( (attrBase == NULL)
	  || (attrBase[0].pValue == NULL)
	  || (attrBase[0].ulValueLen < LUNA_MEMCMP_MIN_LEN)
	   )
		{
		fprintf(stderr, LUNA_FUNC_NAME": attrBase invalid.\n");
		goto err;
		}

	/* FindObjectsInit */
	if (retCode == CKR_OK)
		{
		retCode = p11.std->C_FindObjectsInit(ctx->hSession, pAttr, nAttr);
		have_init = (retCode == CKR_OK) ? 1 : 0;
		}
		
	/* FindObjects */
	if (retCode == CKR_OK)
		{
		do
			{
			retLoop = CKR_GENERAL_ERROR; /* initially assume error */
			handles[0] = 0;
			obj_count = 0;    
			retCode = p11.std->C_FindObjects(ctx->hSession, &handles[0], 1, &obj_count);
			if ( (retCode == CKR_OK) && (obj_count == 1) && (handles[0] != LUNA_INVALID_HANDLE) )
				{
				attrFoo[0].type = attrBase[0].type;
				attrFoo[0].pValue = NULL;
				attrFoo[0].ulValueLen = 0;
				if (luna_attribute_malloc(ctx, handles[0], attrFoo))
					{
					retLoop = CKR_OK; /* continue looping */
					if (luna_memcmp_rev_inexact(
					  (CK_BYTE_PTR)attrBase[0].pValue, attrBase[0].ulValueLen,
					  (CK_BYTE_PTR)attrFoo[0].pValue, attrFoo[0].ulValueLen) == 0)
						{
						/* found a match... maybe not the only match */
						match_count++;
						match_handle = handles[0];
						}
					
					/* Undo luna_attribute_malloc */
					luna_attribute_free(attrFoo);
					}
				else
					{
					/* failing to get attribute constitutes total failure */
					retCodeTotal = retLoop = CKR_GENERAL_ERROR;
					}
				}
			else
				{
				/* failing to iterate constitutes total failure */
				if (retCode != CKR_OK)
					{
					retCodeTotal = retLoop = retCode;
					}
				}
			}
		while (retLoop == CKR_OK);
		}
	
	/* FindObjectsFinal */
	if (have_init)
		{
		(void)p11.std->C_FindObjectsFinal(ctx->hSession);
		have_init = 0;
		}

	/* Undo luna_attribute_malloc */
	luna_attribute_free(attrFoo);
	
	/* Check result (silent) */
	if (match_count < 1) goto err;

	/* Check result (non-silent) */
	if (match_count != 1)
		{
		fprintf(stderr, LUNA_FUNC_NAME": match_count != 1.\n");
		goto err;
		}
	
	/* Return success */
	(*pHandle) = match_handle;
	return 1;

err:
	/* Return failure */
	(*pHandle) = LUNA_INVALID_HANDLE;
	return 0;
	}

#undef LUNA_FUNC_NAME
#define LUNA_FUNC_NAME  "luna_find_ecdsa_handle"

/* find ecdsa key (typically for deletion) */
static CK_OBJECT_HANDLE
luna_find_ecdsa_handle(luna_context_t *ctx, EC_KEY *dsa, int bPrivate)
	{
	CK_OBJECT_HANDLE rethandle = CK_INVALID_HANDLE; 
	
	int rcSize1 = -1;
	CK_BYTE_PTR bufP = NULL;
	CK_BYTE_PTR bufQ = NULL;
	CK_ULONG rcCount = 0;
	CK_ULONG rcBase = 0;
	CK_OBJECT_HANDLE tmphandle = CK_INVALID_HANDLE; 
	CK_OBJECT_CLASS ulClass = 0;
	CK_KEY_TYPE ulKeyType = 0;
	
	CK_ATTRIBUTE attrib[6];
	CK_ATTRIBUTE attribId[1];
	CK_ATTRIBUTE attribPoint[1];

	memset(attrib, 0, sizeof(attrib));
	memset(attribId, 0, sizeof(attribId));
	memset(attribPoint, 0, sizeof(attribPoint));

	/* Define base attributes (common to public and private key) */
	rcCount = 0;
	
	ulKeyType = CKK_EC;
	attrib[rcCount].type = CKA_KEY_TYPE;
	attrib[rcCount].pValue = &ulKeyType;
	attrib[rcCount].ulValueLen = sizeof(ulKeyType);
	rcCount++;

	if ( (rcSize1 = i2d_ECParameters(dsa, &bufP)) < 1 ) goto done;
	attrib[rcCount].type = CKA_EC_PARAMS;
	attrib[rcCount].pValue = bufP;
	attrib[rcCount].ulValueLen = (CK_ULONG)rcSize1;
	rcCount++;

	/* Define public key attributes */
	rcBase = rcCount;
	
	ulClass = CKO_PUBLIC_KEY;
	attrib[rcCount].type = CKA_CLASS;
	attrib[rcCount].pValue = &ulClass;
	attrib[rcCount].ulValueLen = sizeof(ulClass);
	rcCount++;

	/* NOTE: i2o_ECPublicKey does not encode the exact same CKA_EC_POINT found on token! */
	if ( (rcSize1 = i2o_ECPublicKey(dsa, &bufQ)) < 1 ) goto done;
	attribPoint[0].type = CKA_EC_POINT;
	attribPoint[0].pValue = bufQ;
	attribPoint[0].ulValueLen = (CK_ULONG)rcSize1;

	/* Find public key (using inexact search algorithm; see i2o_ECPublicKey) */
	if (!luna_find_object_inexact(ctx, attrib, rcCount, &tmphandle, attribPoint))
		{
		fprintf(stderr, LUNA_FUNC_NAME": luna_find_object_inexact.\n");
		goto done;
		}

	/* Find private key using CKA_ID of public key */
	if (bPrivate)
		{
		attribId[0].type = CKA_ID;
		attribId[0].pValue = NULL_PTR;
		attribId[0].ulValueLen = 0;
		if (!luna_attribute_malloc(ctx, tmphandle, attribId))
			{
			fprintf(stderr, LUNA_FUNC_NAME": luna_attribute_malloc.\n");
			goto done;
			}
			
		/* Define private key attributes */
		rcCount = rcBase;
		
		ulClass = CKO_PRIVATE_KEY; 
		attrib[rcCount].type = CKA_CLASS; 
		attrib[rcCount].pValue = &ulClass; 
		attrib[rcCount].ulValueLen = sizeof(ulClass); 
		rcCount++;

		attrib[rcCount] = attribId[0]; /* copy struct */
		rcCount++;

		/* Find private key; must be unique */
		if (!luna_find_object_ex1(ctx, attrib, rcCount, &tmphandle, 0))
			{
			fprintf(stderr, LUNA_FUNC_NAME": luna_find_object_ex1.\n");
			goto done;
			}
		}
	
	/* on success, set 'rethandle' */
	rethandle = tmphandle;
		
done:
	/* undo luna_attribute_malloc */
	luna_attribute_free(attribId);

	/* undo i2d_ECParameters */
	if (bufP != NULL) 
		{
		OPENSSL_free(bufP); bufP = NULL;
		}
		
	/* undo i2o_ECPublicKey */
	if (bufQ != NULL) 
		{
		OPENSSL_free(bufQ); bufQ = NULL;
		}
		
	return rethandle;
	}

#if (0) /* dead code */
/* extract encoded "EC_KEY->priv_key" */
static unsigned _luna_ecdsa_priv2bin(EC_KEY *dsa, CK_BYTE_PTR *in)
	{
	CK_BYTE baHeader[] = { 's', 'a', 'u', 't', 'i', 'l', ':', 'C', 'K', 'A', '_', 'I', 'D', ':'  };
	unsigned num = 0;
	CK_BYTE_PTR bufX = NULL;
	CK_BYTE_PTR bufW = NULL;

		/* check null */
	if (dsa == NULL) goto err;
	if (dsa->priv_key == NULL) goto err;
		/* CKA_ID should size of sha1 hash or larger */
	if ((num = BN_num_bytes(dsa->priv_key)) < (sizeof(baHeader) + 20)) goto err;
		/* check out of memory */
	if ((bufX = (CK_BYTE_PTR)LUNA_malloc(num)) == NULL) goto err;
	if ((bufW = (CK_BYTE_PTR)LUNA_malloc(num)) == NULL) goto err;
	if (num != BN_bn2bin(dsa->priv_key, bufX)) goto err;
		/* check the encoding */
	if (memcmp(baHeader, bufX, sizeof(baHeader)) != 0) goto err; 
	if (in != NULL)
		{
		memcpy(bufW, (bufX + sizeof(baHeader)), (num - sizeof(baHeader)));
		(*in) = bufW;
		}
	else
		{
		LUNA_free(bufW); bufW = NULL;
		}
	LUNA_free(bufX); bufX = NULL;
	return (num - sizeof(baHeader));

err:
	
	if (bufW != NULL) LUNA_free(bufW);
	if (bufX != NULL) LUNA_free(bufX);
	return 0;
	}
#endif

#endif /* LUNA_OSSL_ECDSA */

/*****************************************************************************/

/* Support C or C++ compiler in the field */
#ifdef __cplusplus
}
#endif

/* eof */
