/*
 * 15.07.02: Ported to VMS
 */
/*
 * scapi.c
 *
 */

#ifdef __vms
#include "net-snmp-config.h"
#else
#include <net-snmp/net-snmp-config.h>
#endif

#include <sys/types.h>
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef __vms
#include "snmp_types.h"
#include "snmp_output_api.h"
#include "snmp_utilities.h"
#else
#include <net-snmp/types.h>
#include <net-snmp/output_api.h>
#include <net-snmp/utilities.h>
#endif
#ifdef USE_INTERNAL_MD5
#include <net-snmp/library/md5.h>
#endif
#ifdef __vms
#include "snmp_api.h"
#include "snmp_lib_callback.h"
#include "snmp_secmod.h"
#include "snmpusm.h"
#include "snmp_lib_keytools.h"
#include "snmp_lib_scapi.h"
#include "snmp_lib_mib.h"
#include "snmp_lib_transform_oids.h"
#else
#include <net-snmp/library/snmp_api.h>
#include <net-snmp/library/callback.h>
#include <net-snmp/library/snmp_secmod.h>
#include <net-snmp/library/snmpusm.h>
#include <net-snmp/library/keytools.h>
#include <net-snmp/library/scapi.h>
#include <net-snmp/library/mib.h>
#include <net-snmp/library/transform_oids.h>
#endif

#ifdef USE_OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

#ifdef QUITFUN
#undef QUITFUN
#define QUITFUN(e, l)					\
	if (e != SNMPERR_SUCCESS) {			\
		rval = SNMPERR_SC_GENERAL_FAILURE;	\
		goto l ;				\
	}
#endif


/*
 * sc_get_properlength(oid *hashtype, u_int hashtype_len):
 * 
 * Given a hashing type ("hashtype" and its length hashtype_len), return
 * the length of the hash result.
 * 
 * Returns either the length or SNMPERR_GENERR for an unknown hashing type.
 */
int
sc_get_properlength(const oid * hashtype, u_int hashtype_len)
{
    DEBUGTRACE;
    /*
     * Determine transform type hash length.
     */
    if (ISTRANSFORM(hashtype, HMACMD5Auth)) {
        return BYTESIZE(SNMP_TRANS_AUTHLEN_HMACMD5);
    } else if (ISTRANSFORM(hashtype, HMACSHA1Auth)) {
        return BYTESIZE(SNMP_TRANS_AUTHLEN_HMACSHA1);
    }
    return SNMPERR_GENERR;
}


/*******************************************************************-o-******
 * sc_init
 *
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 */
int
sc_init(void)
{
    int             rval = SNMPERR_SUCCESS;

#ifndef USE_OPENSSL
#ifdef USE_INTERNAL_MD5
    struct timeval  tv;

    DEBUGTRACE;

    gettimeofday(&tv, (struct timezone *) 0);

    srandom(tv.tv_sec ^ tv.tv_usec);
#else
    rval = SNMPERR_SC_NOT_CONFIGURED;
#endif
    /*
     * XXX ogud: The only reason to do anything here with openssl is to 
     * * XXX ogud: seed random number generator 
     */
#endif                          /* ifndef USE_OPENSSL */
    return rval;
}                               /* end sc_init() */

/*******************************************************************-o-******
 * sc_random
 *
 * Parameters:
 *	*buf		Pre-allocated buffer.
 *	*buflen 	Size of buffer.
 *      
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 */
int
sc_random(u_char * buf, size_t * buflen)
#if defined(USE_INTERNAL_MD5) || defined(USE_OPENSSL)
{
    int             rval = SNMPERR_SUCCESS;
#ifdef USE_INTERNAL_MD5
    int             i;
    int             rndval;
    u_char         *ucp = buf;
#endif

    DEBUGTRACE;

#ifdef USE_OPENSSL
    RAND_bytes(buf, *buflen);   /* will never fail */
#else                           /* USE_INTERNAL_MD5 */
    /*
     * fill the buffer with random integers.  Note that random()
     * is defined in config.h and may not be truly the random()
     * system call if something better existed 
     */
    rval = *buflen - *buflen % sizeof(rndval);
    for (i = 0; i < rval; i += sizeof(rndval)) {
        rndval = random();
        memcpy(ucp, &rndval, sizeof(rndval));
        ucp += sizeof(rndval);
    }

    rndval = random();
    memcpy(ucp, &rndval, *buflen % sizeof(rndval));

    rval = SNMPERR_SUCCESS;
#endif                          /* USE_OPENSSL */
    return rval;

}                               /* end sc_random() */

#else
_SCAPI_NOT_CONFIGURED
#endif                          /*  */
/*******************************************************************-o-******
 * sc_generate_keyed_hash
 *
 * Parameters:
 *	 authtype	Type of authentication transform.
 *	 authtypelen
 *	*key		Pointer to key (Kul) to use in keyed hash.
 *	 keylen		Length of key in bytes.
 *	*message	Pointer to the message to hash.
 *	 msglen		Length of the message.
 *	*MAC		Will be returned with allocated bytes containg hash.
 *	*maclen		Length of the hash buffer in bytes; also indicates
 *				whether the MAC should be truncated.
 *      
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 *	SNMPERR_GENERR			All errs
 *
 *
 * A hash of the first msglen bytes of message using a keyed hash defined
 * by authtype is created and stored in MAC.  MAC is ASSUMED to be a buffer
 * of at least maclen bytes.  If the length of the hash is greater than
 * maclen, it is truncated to fit the buffer.  If the length of the hash is
 * less than maclen, maclen set to the number of hash bytes generated.
 *
 * ASSUMED that the number of hash bits is a multiple of 8.
 */
     int















      
         
         
         
         
         
         
         
         
         
         
         
         
         
         
         sc_generate_keyed_hash(const oid * authtype, size_t authtypelen,
                                u_char * key, u_int keylen,
                                u_char * message, u_int msglen,
                                u_char * MAC, size_t * maclen)
#if  defined(USE_INTERNAL_MD5) || defined(USE_OPENSSL)
{
    int             rval = SNMPERR_SUCCESS;
    int             properlength;

    u_char          buf[SNMP_MAXBUF_SMALL];
#if  defined(USE_OPENSSL)
    int             buf_len = sizeof(buf);
#endif

    DEBUGTRACE;

#ifdef SNMP_TESTING_CODE
    {
        int             i;
        DEBUGMSG(("sc_generate_keyed_hash",
                  "sc_generate_keyed_hash(): key=0x"));
        for (i = 0; i < keylen; i++)
            DEBUGMSG(("sc_generate_keyed_hash", "%02x", key[i] & 0xff));
        DEBUGMSG(("sc_generate_keyed_hash", " (%d)\n", keylen));
    }
#endif                          /* SNMP_TESTING_CODE */

    /*
     * Sanity check.
     */
    if (!authtype || !key || !message || !MAC || !maclen
        || (keylen <= 0) || (msglen <= 0) || (*maclen <= 0)
        || (authtypelen != USM_LENGTH_OID_TRANSFORM)) {
        QUITFUN(SNMPERR_GENERR, sc_generate_keyed_hash_quit);
    }

    properlength = sc_get_properlength(authtype, authtypelen);
    if (properlength == SNMPERR_GENERR)
        return properlength;

    if (((int) keylen < properlength)) {
        QUITFUN(SNMPERR_GENERR, sc_generate_keyed_hash_quit);
    }
#ifdef USE_OPENSSL
    /*
     * Determine transform type.
     */
    if (ISTRANSFORM(authtype, HMACMD5Auth))
        HMAC(EVP_md5(), key, keylen, message, msglen, buf, &buf_len);
    else if (ISTRANSFORM(authtype, HMACSHA1Auth))
        HMAC(EVP_sha1(), key, keylen, message, msglen, buf, &buf_len);
    else {
        QUITFUN(SNMPERR_GENERR, sc_generate_keyed_hash_quit);
    }
    if (buf_len != properlength) {
        QUITFUN(rval, sc_generate_keyed_hash_quit);
    }
    if (*maclen > buf_len)
        *maclen = buf_len;
    memcpy(MAC, buf, *maclen);
#else
    if ((int) *maclen > properlength)
        *maclen = properlength;
    if (MDsign(message, msglen, MAC, *maclen, key, keylen)) {
        rval = SNMPERR_GENERR;
        goto sc_generate_keyed_hash_quit;
    }
#endif                          /* USE_OPENSSL */

#ifdef SNMP_TESTING_CODE
    {
        char           *s;
        int             len = binary_to_hex(MAC, *maclen, &s);

        DEBUGMSGTL(("scapi", "Full v3 message hash: %s\n", s));
        SNMP_ZERO(s, len);
        SNMP_FREE(s);
    }
#endif

  sc_generate_keyed_hash_quit:
    SNMP_ZERO(buf, SNMP_MAXBUF_SMALL);
    return rval;
}                               /* end sc_generate_keyed_hash() */

#else
                _SCAPI_NOT_CONFIGURED
#endif                          /* */
/*
 * sc_hash(): a generic wrapper around whatever hashing package we are using.
 * 
 * IN:
 * hashtype    - oid pointer to a hash type
 * hashtypelen - length of oid pointer
 * buf         - u_char buffer to be hashed
 * buf_len     - integer length of buf data
 * MAC_len     - length of the passed MAC buffer size.
 * 
 * OUT:    
 * MAC         - pre-malloced space to store hash output.
 * MAC_len     - length of MAC output to the MAC buffer.
 * 
 * Returns:
 * SNMPERR_SUCCESS              Success.
 * SNMP_SC_GENERAL_FAILURE      Any error.
 */
     int















      
         
         
         
         
         
         
         
         
         
         
         
         
         
         
         sc_hash(const oid * hashtype, size_t hashtypelen, u_char * buf,
                 size_t buf_len, u_char * MAC, size_t * MAC_len)
#if defined(USE_INTERNAL_MD5) || defined(USE_OPENSSL)
{
    int             rval = SNMPERR_SUCCESS;

#ifdef USE_OPENSSL
    EVP_MD         *hash(void);
    HMAC_CTX       *c = NULL;
#endif

    DEBUGTRACE;

    if (hashtype == NULL || hashtypelen < 0 || buf == NULL ||
        buf_len < 0 || MAC == NULL || MAC_len == NULL ||
        (int) (*MAC_len) < sc_get_properlength(hashtype, hashtypelen))
        return (SNMPERR_GENERR);

#ifdef USE_OPENSSL
    /*
     * Determine transform type.
     */
    c = malloc(sizeof(HMAC_CTX));
    if (c == NULL)
        return (SNMPERR_GENERR);

    if (ISTRANSFORM(hashtype, HMACMD5Auth)) {
        EVP_DigestInit(&c->md_ctx, (const EVP_MD *) EVP_md5());
    } else if (ISTRANSFORM(hashtype, HMACSHA1Auth)) {
        EVP_DigestInit(&c->md_ctx, (const EVP_MD *) EVP_sha1());
    } else {
        return (SNMPERR_GENERR);
    }
    EVP_DigestUpdate(&c->md_ctx, buf, buf_len);
    EVP_DigestFinal(&(c->md_ctx), MAC, MAC_len);
    free(c);
    return (rval);
#else                           /* USE_INTERNAL_MD5 */

    if (MDchecksum(buf, buf_len, MAC, *MAC_len)) {
        return SNMPERR_GENERR;
    }
    if (*MAC_len > 16)
        *MAC_len = 16;
    return SNMPERR_SUCCESS;

#endif                          /* USE_OPENSSL */
}
#else                           /* !defined(USE_OPENSSL) && !defined(USE_INTERNAL_MD5) */
_SCAPI_NOT_CONFIGURED
#endif                          /* !defined(USE_OPENSSL) && !defined(USE_INTERNAL_MD5) */
/*******************************************************************-o-******
 * sc_check_keyed_hash
 *
 * Parameters:
 *	 authtype	Transform type of authentication hash.
 *	*key		Key bits in a string of bytes.
 *	 keylen		Length of key in bytes.
 *	*message	Message for which to check the hash.
 *	 msglen		Length of message.
 *	*MAC		Given hash.
 *	 maclen		Length of given hash; indicates truncation if it is
 *				shorter than the normal size of output for
 *				given hash transform.
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 *	SNMP_SC_GENERAL_FAILURE	Any error
 *
 *
 * Check the hash given in MAC against the hash of message.  If the length
 * of MAC is less than the length of the transform hash output, only maclen
 * bytes are compared.  The length of MAC cannot be greater than the
 * length of the hash transform output.
 */
     int















      
         
         
         
         
         
         
         
         
         
         
         
         
         
         
         sc_check_keyed_hash(const oid * authtype, size_t authtypelen,
                             u_char * key, u_int keylen,
                             u_char * message, u_int msglen,
                             u_char * MAC, u_int maclen)
#if defined(USE_INTERNAL_MD5) || defined(USE_OPENSSL)
{
    int             rval = SNMPERR_SUCCESS;
    size_t          buf_len = SNMP_MAXBUF_SMALL;

    u_char          buf[SNMP_MAXBUF_SMALL];

    DEBUGTRACE;

#ifdef SNMP_TESTING_CODE
    {
        int             i;
        DEBUGMSG(("scapi", "sc_check_keyed_hash():    key=0x"));
        for (i = 0; i < keylen; i++)
            DEBUGMSG(("scapi", "%02x", key[i] & 0xff));
        DEBUGMSG(("scapi", " (%d)\n", keylen));
    }
#endif                          /* SNMP_TESTING_CODE */

    /*
     * Sanity check.
     */
    if (!authtype || !key || !message || !MAC
        || (keylen <= 0) || (msglen <= 0) || (maclen <= 0)
        || (authtypelen != USM_LENGTH_OID_TRANSFORM)) {
        QUITFUN(SNMPERR_GENERR, sc_check_keyed_hash_quit);
    }


    /*
     * Generate a full hash of the message, then compare
     * the result with the given MAC which may shorter than
     * the full hash length.
     */
    rval = sc_generate_keyed_hash(authtype, authtypelen,
                                  key, keylen,
                                  message, msglen, buf, &buf_len);
    QUITFUN(rval, sc_check_keyed_hash_quit);

    if (maclen > msglen) {
        QUITFUN(SNMPERR_GENERR, sc_check_keyed_hash_quit);

    } else if (memcmp(buf, MAC, maclen) != 0) {
        QUITFUN(SNMPERR_GENERR, sc_check_keyed_hash_quit);
    }


  sc_check_keyed_hash_quit:
    SNMP_ZERO(buf, SNMP_MAXBUF_SMALL);

    return rval;

}                               /* end sc_check_keyed_hash() */

#else
_SCAPI_NOT_CONFIGURED
#endif                          /* USE_INTERNAL_MD5 */
/*******************************************************************-o-******
 * sc_encrypt
 *
 * Parameters:
 *	 privtype	Type of privacy cryptographic transform.
 *	*key		Key bits for crypting.
 *	 keylen		Length of key (buffer) in bytes.
 *	*iv		IV bits for crypting.
 *	 ivlen		Length of iv (buffer) in bytes.
 *	*plaintext	Plaintext to crypt.
 *	 ptlen		Length of plaintext.
 *	*ciphertext	Ciphertext to crypt.
 *	*ctlen		Length of ciphertext.
 *      
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 *	SNMPERR_SC_NOT_CONFIGURED	Encryption is not supported.
 *	SNMPERR_SC_GENERAL_FAILURE	Any other error
 *
 *
 * Encrypt plaintext into ciphertext using key and iv.
 *
 * ctlen contains actual number of crypted bytes in ciphertext upon
 * successful return.
 */
     int















      
         
         
         
         
         
         
         
         
         
         
         
         
         
         
         sc_encrypt(const oid * privtype, size_t privtypelen,
                    u_char * key, u_int keylen,
                    u_char * iv, u_int ivlen,
                    u_char * plaintext, u_int ptlen,
                    u_char * ciphertext, size_t * ctlen)
#if defined(USE_OPENSSL)
{
    int             rval = SNMPERR_SUCCESS;
    u_int           properlength, properlength_iv;
    u_char          pad_block[32];      /* bigger than anything I need */
    u_char          my_iv[32];  /* ditto */
    int             pad, plast, pad_size;
    des_key_schedule key_sch;
    des_cblock      key_struct;

    DEBUGTRACE;

    /*
     * Sanity check.
     */
#if	!defined(SCAPI_AUTHPRIV)
    snmp_log(LOG_ERR, "Encryption support not enabled. %d\n",__LINE__);
    snmp_log(LOG_ERR, "Encryption support not enabled.\n");
    return SNMPERR_SC_NOT_CONFIGURED;
#endif

    if (!privtype || !key || !iv || !plaintext || !ciphertext || !ctlen
        || (keylen <= 0) || (ivlen <= 0) || (ptlen <= 0) || (*ctlen <= 0)
        || (privtypelen != USM_LENGTH_OID_TRANSFORM)) {
        QUITFUN(SNMPERR_GENERR, sc_encrypt_quit);
    } else if (ptlen > *ctlen) {
        QUITFUN(SNMPERR_GENERR, sc_encrypt_quit);
    }
#ifdef SNMP_TESTING_CODE
    {
        size_t          buf_len = 128, out_len = 0;
        u_char         *buf = (u_char *) malloc(buf_len);

        if (buf != NULL) {
            if (sprint_realloc_hexstring(&buf, &buf_len, &out_len, 1,
                                         iv, ivlen)) {
                DEBUGMSGTL(("scapi", "encrypt: IV: %s/", buf));
            } else {
                DEBUGMSGTL(("scapi", "encrypt: IV: %s [TRUNCATED]/", buf));
            }
            out_len = 0;
            if (sprint_realloc_hexstring(&buf, &buf_len, &out_len, 1,
                                         key, keylen)) {
                DEBUGMSG(("scapi", "%s\n", buf));
            } else {
                DEBUGMSG(("scapi", "%s [TRUNCATED]\n", buf));
            }
            out_len = 0;
            if (sprint_realloc_hexstring(&buf, &buf_len, &out_len, 1,
                                         plaintext, 16)) {
                DEBUGMSGTL(("scapi", "encrypt: string: %s\n", buf));
            } else {
                DEBUGMSGTL(("scapi", "encrypt: string: %s [TRUNCATED]\n",
                            buf));
            }
            free(buf);
        } else {
            DEBUGMSGTL(("scapi",
                        "encrypt: malloc fail for debug output\n"));
        }
    }
#endif                          /* SNMP_TESTING_CODE */


    /*
     * Determine privacy transform.
     */
    if (ISTRANSFORM(privtype, DESPriv)) {
        properlength = BYTESIZE(SNMP_TRANS_PRIVLEN_1DES);
        properlength_iv = BYTESIZE(SNMP_TRANS_PRIVLEN_1DES_IV);
        pad_size = properlength;
    } else {
        QUITFUN(SNMPERR_GENERR, sc_encrypt_quit);
    }

    if ((keylen < properlength) || (ivlen < properlength_iv)) {
        QUITFUN(SNMPERR_GENERR, sc_encrypt_quit);
    }

    /*
     * now calculate the padding needed 
     */
    pad = pad_size - (ptlen % pad_size);
    plast = (int) ptlen - (pad_size - pad);
    if (pad == pad_size)
        pad = 0;
    if (ptlen + pad > *ctlen) {
        QUITFUN(SNMPERR_GENERR, sc_encrypt_quit);       /* not enough space */
    }
    if (pad > 0) {              /* copy data into pad block if needed */
        memcpy(pad_block, plaintext + plast, pad_size - pad);
        memset(&pad_block[pad_size - pad], pad, pad);   /* filling in padblock */
    }

    memset(my_iv, 0, sizeof(my_iv));

    if (ISTRANSFORM(privtype, DESPriv)) {
        memcpy(key_struct, key, sizeof(key_struct));
        (void) des_key_sched(&key_struct, key_sch);

        memcpy(my_iv, iv, ivlen);
        /*
         * encrypt the data 
         */
        des_ncbc_encrypt(plaintext, ciphertext, plast, key_sch,
                         (des_cblock *) my_iv, DES_ENCRYPT);
        if (pad > 0) {
            /*
             * then encrypt the pad block 
             */
            des_ncbc_encrypt(pad_block, ciphertext + plast, pad_size,
                             key_sch, (des_cblock *) my_iv, DES_ENCRYPT);
            *ctlen = plast + pad_size;
        } else {
            *ctlen = plast;
        }
    }
  sc_encrypt_quit:
    /*
     * clear memory just in case 
     */
    memset(my_iv, 0, sizeof(my_iv));
    memset(pad_block, 0, sizeof(pad_block));
    memset(key_struct, 0, sizeof(key_struct));
    memset(key_sch, 0, sizeof(key_sch));
    return rval;

}                               /* end sc_encrypt() */

#else
{
#	if USE_INTERNAL_MD5
    {
    snmp_log(LOG_ERR, "Encryption support not enabled. %d\n",__LINE__);
        snmp_log(LOG_ERR, "Encryption support not enabled.\n");
        DEBUGMSGTL(("scapi", "Encrypt function not defined.\n"));
        return SNMPERR_SC_GENERAL_FAILURE;
    }

#	else
    _SCAPI_NOT_CONFIGURED
#	endif                   /* USE_INTERNAL_MD5 */
}
#endif                          /* */



/*******************************************************************-o-******
 * sc_decrypt
 *
 * Parameters:
 *	 privtype
 *	*key
 *	 keylen
 *	*iv
 *	 ivlen
 *	*ciphertext
 *	 ctlen
 *	*plaintext
 *	*ptlen
 *      
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 *	SNMPERR_SC_NOT_CONFIGURED	Encryption is not supported.
 *      SNMPERR_SC_GENERAL_FAILURE      Any other error
 *
 *
 * Decrypt ciphertext into plaintext using key and iv.
 *
 * ptlen contains actual number of plaintext bytes in plaintext upon
 * successful return.
 */
int
sc_decrypt(const oid * privtype, size_t privtypelen,
           u_char * key, u_int keylen,
           u_char * iv, u_int ivlen,
           u_char * ciphertext, u_int ctlen,
           u_char * plaintext, size_t * ptlen)
#ifdef USE_OPENSSL
{

    int             rval = SNMPERR_SUCCESS;
    u_char         *my_iv[32];
    des_key_schedule key_sch;
    des_cblock      key_struct;
    u_int           properlength, properlength_iv;

    DEBUGTRACE;

    if (!privtype || !key || !iv || !plaintext || !ciphertext || !ptlen
        || (ctlen <= 0) || (*ptlen <= 0) || (*ptlen < ctlen)
        || (privtypelen != USM_LENGTH_OID_TRANSFORM)) {
        QUITFUN(SNMPERR_GENERR, sc_decrypt_quit);
    }
#ifdef SNMP_TESTING_CODE
    {
        size_t          buf_len = 128, out_len = 0;
        u_char         *buf = (u_char *) malloc(buf_len);

        if (buf != NULL) {
            if (sprint_realloc_hexstring(&buf, &buf_len, &out_len, 1,
                                         iv, ivlen)) {
                DEBUGMSGTL(("scapi", "decrypt: IV: %s/", buf));
            } else {
                DEBUGMSGTL(("scapi", "decrypt: IV: %s [TRUNCATED]/", buf));
            }
            out_len = 0;
            if (sprint_realloc_hexstring(&buf, &buf_len, &out_len, 1,
                                         key, keylen)) {
                DEBUGMSG(("scapi", "%s\n", buf));
            } else {
                DEBUGMSG(("scapi", "%s\n", buf));
            }
            free(buf);
        } else {
            DEBUGMSGTL(("scapi",
                        "decrypt: malloc fail for debug output\n"));
        }
    }
#endif                          /* SNMP_TESTING_CODE */

    /*
     * Determine privacy transform.
     */
    if (ISTRANSFORM(privtype, DESPriv)) {
        properlength = BYTESIZE(SNMP_TRANS_PRIVLEN_1DES);
        properlength_iv = BYTESIZE(SNMP_TRANS_PRIVLEN_1DES_IV);

    } else {
        QUITFUN(SNMPERR_GENERR, sc_decrypt_quit);
    }

    if ((keylen < properlength) || (ivlen < properlength_iv)) {
        QUITFUN(SNMPERR_GENERR, sc_decrypt_quit);
    }

    memset(my_iv, 0, sizeof(my_iv));
    if (ISTRANSFORM(privtype, DESPriv)) {
        memcpy(key_struct, key, sizeof(key_struct));
        (void) des_key_sched(&key_struct, key_sch);

        memcpy(my_iv, iv, ivlen);
        des_cbc_encrypt(ciphertext, plaintext, ctlen, key_sch,
                        (des_cblock *) my_iv, DES_DECRYPT);
        *ptlen = ctlen;
    }

    /*
     * exit cond 
     */
  sc_decrypt_quit:
    memset(key_sch, 0, sizeof(key_sch));
    memset(key_struct, 0, sizeof(key_struct));
    memset(my_iv, 0, sizeof(my_iv));
    return rval;
}
#else                           /* USE OPEN_SSL */
{
#if	!defined(SCAPI_AUTHPRIV)
    snmp_log(LOG_ERR, "Encryption support not enabled. %d\n",__LINE__);
    return SNMPERR_SC_NOT_CONFIGURED;
#else
#	if USE_INTERNAL_MD5
    {
        DEBUGMSGTL(("scapi", "Decryption function not defined.\n"));
        return SNMPERR_SC_GENERAL_FAILURE;
    }

#	else
    _SCAPI_NOT_CONFIGURED
#	endif                   /* USE_INTERNAL_MD5 */
#endif                          /*  */
}
#endif                          /* USE_OPENSSL */