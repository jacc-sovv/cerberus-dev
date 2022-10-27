#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto/ecc.h"
#include "crypto/ecc_mbedtls.h"
#include "mbedtls/pk.h"
#include "testing/crypto/ecc_testing.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"


//Print out the private and public keys
//Yo!
struct ecc_public_key public;
struct ecc_private_key private;

//Maybe:
//ecc_mbedtls_test_private_key_init_key_pair_and_sign //init a private key
//Then, do ecc_mbedtls_test_init_public_key_with_private_key

#line 2 "suites/helpers.function"
/*----------------------------------------------------------------------------*/
/* Headers */

#include <stdlib.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#define mbedtls_exit       exit
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#if defined(MBEDTLS_CHECK_PARAMS)
#include "mbedtls/platform_util.h"
#include <setjmp.h>
#endif

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT8 uint8_t;
typedef INT32 int32_t;
typedef UINT32 uint32_t;
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#else
#include <stdint.h>
#endif

#include <string.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#include <strings.h>
#endif

/* Type for Hex parameters */
typedef struct data_tag
{
    uint8_t *   x;
    uint32_t    len;
} data_t;

/*----------------------------------------------------------------------------*/
/* Status and error constants */

#define DEPENDENCY_SUPPORTED            0   /* Dependency supported by build */
#define KEY_VALUE_MAPPING_FOUND         0   /* Integer expression found */
#define DISPATCH_TEST_SUCCESS           0   /* Test dispatch successful */

#define KEY_VALUE_MAPPING_NOT_FOUND     -1  /* Integer expression not found */
#define DEPENDENCY_NOT_SUPPORTED        -2  /* Dependency not supported */
#define DISPATCH_TEST_FN_NOT_FOUND      -3  /* Test function not found */
#define DISPATCH_INVALID_TEST_DATA      -4  /* Invalid test parameter type.
                                               Only int, string, binary data
                                               and integer expressions are
                                               allowed */
#define DISPATCH_UNSUPPORTED_SUITE      -5  /* Test suite not supported by the
                                               build */

typedef enum
{
    PARAMFAIL_TESTSTATE_IDLE = 0,           /* No parameter failure call test */
    PARAMFAIL_TESTSTATE_PENDING,            /* Test call to the parameter failure
                                             * is pending */
    PARAMFAIL_TESTSTATE_CALLED              /* The test call to the parameter
                                             * failure function has been made */
} paramfail_test_state_t;


/*----------------------------------------------------------------------------*/
/* Macros */

/**
 * \brief   This macro tests the expression passed to it as a test step or
 *          individual test in a test case.
 *
 *          It allows a library function to return a value and return an error
 *          code that can be tested.
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), will be assumed to be a test
 *          failure.
 *
 *          This macro is not suitable for negative parameter validation tests,
 *          as it assumes the test step will not create an error.
 *
 *          Failing the test means:
 *          - Mark this test case as failed.
 *          - Print a message identifying the failure.
 *          - Jump to the \c exit label.
 *
 *          This macro expands to an instruction, not an expression.
 *          It may jump to the \c exit label.
 *
 * \param   TEST    The test expression to be tested.
 */
#define TEST_ASSERT( TEST )                                 \
    do {                                                    \
       if( ! (TEST) )                                       \
       {                                                    \
          test_fail( #TEST, __LINE__, __FILE__ );           \
          goto exit;                                        \
       }                                                    \
    } while( 0 )

#if defined(MBEDTLS_CHECK_PARAMS) && !defined(MBEDTLS_PARAM_FAILED_ALT)
/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will fail
 *          and will generate an error.
 *
 *          It allows a library function to return a value and tests the return
 *          code on return to confirm the given error code was returned.
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure, and the test will pass.
 *
 *          This macro is intended for negative parameter validation tests,
 *          where the failing function may return an error value or call
 *          MBEDTLS_PARAM_FAILED() to indicate the error.
 *
 * \param   PARAM_ERROR_VALUE   The expected error code.
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_INVALID_PARAM_RET( PARAM_ERR_VALUE, TEST )                     \
    do {                                                                    \
        test_info.paramfail_test_state = PARAMFAIL_TESTSTATE_PENDING;       \
        if( (TEST) != (PARAM_ERR_VALUE) ||                                  \
            test_info.paramfail_test_state != PARAMFAIL_TESTSTATE_CALLED )  \
        {                                                                   \
            test_fail( #TEST, __LINE__, __FILE__ );                         \
            goto exit;                                                      \
        }                                                                   \
   } while( 0 )

/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will fail
 *          and will generate an error.
 *
 *          It assumes the library function under test cannot return a value and
 *          assumes errors can only be indicated byt calls to
 *          MBEDTLS_PARAM_FAILED().
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure. If MBEDTLS_CHECK_PARAMS is not enabled, no test
 *          can be made.
 *
 *          This macro is intended for negative parameter validation tests,
 *          where the failing function can only return an error by calling
 *          MBEDTLS_PARAM_FAILED() to indicate the error.
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_INVALID_PARAM( TEST )                                          \
    do {                                                                    \
        memcpy(jmp_tmp, param_fail_jmp, sizeof(jmp_buf));                   \
        if( setjmp( param_fail_jmp ) == 0 )                                 \
        {                                                                   \
            TEST;                                                           \
            test_fail( #TEST, __LINE__, __FILE__ );                         \
            goto exit;                                                      \
        }                                                                   \
        memcpy(param_fail_jmp, jmp_tmp, sizeof(jmp_buf));                   \
    } while( 0 )
#endif /* MBEDTLS_CHECK_PARAMS && !MBEDTLS_PARAM_FAILED_ALT */

/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will not fail.
 *
 *          It assumes the library function under test cannot return a value and
 *          assumes errors can only be indicated by calls to
 *          MBEDTLS_PARAM_FAILED().
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure. If MBEDTLS_CHECK_PARAMS is not enabled, no test
 *          can be made.
 *
 *          This macro is intended to test that functions returning void
 *          accept all of the parameter values they're supposed to accept - eg
 *          that they don't call MBEDTLS_PARAM_FAILED() when a parameter
 *          that's allowed to be NULL happens to be NULL.
 *
 *          Note: for functions that return something other that void,
 *          checking that they accept all the parameters they're supposed to
 *          accept is best done by using TEST_ASSERT() and checking the return
 *          value as well.
 *
 *          Note: this macro is available even when #MBEDTLS_CHECK_PARAMS is
 *          disabled, as it makes sense to check that the functions accept all
 *          legal values even if this option is disabled - only in that case,
 *          the test is more about whether the function segfaults than about
 *          whether it invokes MBEDTLS_PARAM_FAILED().
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_VALID_PARAM( TEST )                                    \
    TEST_ASSERT( ( TEST, 1 ) );

#define assert(a) if( !( a ) )                                      \
{                                                                   \
    mbedtls_fprintf( stderr, "Assertion Failed at %s:%d - %s\n",   \
                             __FILE__, __LINE__, #a );              \
    mbedtls_exit( 1 );                                             \
}

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif


/*----------------------------------------------------------------------------*/
/* Global variables */



#if defined(MBEDTLS_PLATFORM_C)
mbedtls_platform_context platform_ctx;
#endif

#if defined(MBEDTLS_CHECK_PARAMS)
jmp_buf param_fail_jmp;
jmp_buf jmp_tmp;
#endif

/*----------------------------------------------------------------------------*/
/* Helper flags for complex dependencies */

/* Indicates whether we expect mbedtls_entropy_init
 * to initialize some strong entropy source. */
#if defined(MBEDTLS_TEST_NULL_ENTROPY) ||             \
    ( !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES) && \
      ( !defined(MBEDTLS_NO_PLATFORM_ENTROPY)  ||     \
         defined(MBEDTLS_HAVEGE_C)             ||     \
         defined(MBEDTLS_ENTROPY_HARDWARE_ALT) ||     \
         defined(ENTROPY_NV_SEED) ) )
#define ENTROPY_HAVE_STRONG
#endif


/*----------------------------------------------------------------------------*/
/* Helper Functions */







#if defined(MBEDTLS_CHECK_PARAMS)
void mbedtls_param_failed( const char *failure_condition,
                           const char *file,
                           int line )
{
    /* If we are testing the callback function...  */
    if( test_info.paramfail_test_state == PARAMFAIL_TESTSTATE_PENDING )
    {
        test_info.paramfail_test_state = PARAMFAIL_TESTSTATE_CALLED;
    }
    else
    {
        /* ...else we treat this as an error */

        /* Record the location of the failure, but not as a failure yet, in case
         * it was part of the test */
        test_fail( failure_condition, line, file );
        test_info.failed = 0;

        longjmp( param_fail_jmp, 1 );
    }
}
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))




#endif /* __unix__ || __APPLE__ __MACH__ */




typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;



/**
 * Info structure for the pseudo random function
 *
 * Key should be set at the start to a test-unique value.
 * Do not forget endianness!
 * State( v0, v1 ) should be set to zero.
 */
typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;



int hexcmp( uint8_t * a, uint8_t * b, uint32_t a_len, uint32_t b_len )
{
    int ret = 0;
    uint32_t i = 0;

    if( a_len != b_len )
        return( -1 );

    for( i = 0; i < a_len; i++ )
    {
        if( a[i] != b[i] )
        {
            ret = -1;
            break;
        }
    }
    return ret;
}

#define BUF_BYTES 66
#define ELLIPTIC_CURVE MBEDTLS_ECP_DP_SECP256R1
    // Safe to use the largest buffer size

// Size of buffer used to translate mbed TLS error codes into a string representation
unsigned char pub_key_buffer[1000];
size_t pub_key_len;
unsigned char * yet_another(){
    mbedtls_ecdh_context ctx_cli, ctx_srv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char cli_to_srv_x[BUF_BYTES];
    unsigned char cli_to_srv_y[BUF_BYTES];
    unsigned char srv_to_cli_x[BUF_BYTES];
    unsigned char srv_to_cli_y[BUF_BYTES];
    const char pers[] = "ecdh";

    //Since this has the context, this is probably the right way to go!! (can ecrypt and decrypt with context)
    mbedtls_ecdh_init( &ctx_cli );
    mbedtls_ecdh_init( &ctx_srv );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, sizeof pers );
    mbedtls_ecp_group_load( &ctx_cli.grp,     // Destination group
                                  ELLIPTIC_CURVE ); // Index in the list of well-known domain parameters
    mbedtls_ecdh_gen_public( &ctx_cli.grp,            // ECP group
                                   &ctx_cli.d,              // Destination MPI (secret exponent, aka private key)
                                   &ctx_cli.Q,              // Destination point (public key)
                                   mbedtls_ctr_drbg_random, // RNG function
                                   &ctr_drbg );             //RNG parameter
    mbedtls_mpi_write_binary( &ctx_cli.Q.X,   // Source MPI
                                    cli_to_srv_x,   // Output buffer
                                    BUF_BYTES );    // Output buffer size 
        
    mbedtls_mpi_write_binary( &ctx_cli.Q.Y,   // Source MPI
                                    cli_to_srv_y,   // Output buffer
                                    BUF_BYTES );    // Output buffer size


    //Setting up the server keys

    mbedtls_ecp_group_load( &ctx_srv.grp, ELLIPTIC_CURVE );
    mbedtls_ecdh_gen_public( &ctx_srv.grp, &ctx_srv.d, &ctx_srv.Q, mbedtls_ctr_drbg_random, &ctr_drbg );
    
    mbedtls_mpi_write_binary( &ctx_srv.Q.X, srv_to_cli_x, BUF_BYTES );
    mbedtls_mpi_write_binary( &ctx_srv.Q.Y, srv_to_cli_y, BUF_BYTES );

    mbedtls_mpi_lset( &ctx_srv.Qp.Z,  // MPI to set
                            1 );            // Value to use

    mbedtls_mpi_read_binary( &ctx_srv.Qp.X,   // Destination MPI
                                   cli_to_srv_x,    // Input buffer
                                   BUF_BYTES );     // Input buffer size

    mbedtls_mpi_read_binary( &ctx_srv.Qp.Y,   // Destination MPI
                                   cli_to_srv_y,    // Input buffer
                                   BUF_BYTES );     // Input buffer size

    mbedtls_ecdh_compute_shared( &ctx_srv.grp,            // ECP group
                                       &ctx_srv.z,              // Destination MPI (shared secret)
                                       &ctx_srv.Qp,             // Public key from other party
                                       &ctx_srv.d,              // Our secret exponent (private key)
                                       mbedtls_ctr_drbg_random, // RNG function - countermeasure against timing attacks
                                       &ctr_drbg );             // RNG parameter

    mbedtls_mpi_lset( &ctx_cli.Qp.Z, 1 );    
    mbedtls_mpi_read_binary( &ctx_cli.Qp.X, srv_to_cli_x, BUF_BYTES );
    mbedtls_mpi_read_binary( &ctx_cli.Qp.Y, srv_to_cli_y, BUF_BYTES );
    //Use mbedtls_ecp_point_read_string to make Qp1, see if that's the same as Qp after we generate shared secret

    //This writes our Qp into a character buffer
    size_t x_len;
    unsigned char xbuff[1000];
    mbedtls_ecp_point_write_binary(&ctx_cli.grp, &ctx_cli.Qp, MBEDTLS_ECP_PF_COMPRESSED, &x_len, xbuff, sizeof(xbuff));

    //Use this character buffer to compute a new point, check the shared secret, be sure they are same
    printf("About to print XBUFF\n");
    printf("len is %d", x_len);
    for(int i = 0; i < (int)x_len; i++){
        printf("%c", xbuff[i]);
    }
    printf("\n");

    //Also write it to global variable buffer

    mbedtls_ecp_point_write_binary(&ctx_cli.grp, &ctx_cli.Qp, MBEDTLS_ECP_PF_COMPRESSED, &pub_key_len, pub_key_buffer, sizeof(pub_key_buffer));
    printf("Printing pub key bufffer\n");
    printf("len is %d", pub_key_len);
    printf("In makekeys, using strlen, pubkey is %d", strlen((const char*)pub_key_buffer));
    for(int i = 0; i < (int)pub_key_len; i++){
        printf("%c", pub_key_buffer[i]);
    }
    printf("\n");



    //This tests that the character buffer is sufficient, and we can generate a new point from that character buffer.
    mbedtls_ecp_point testPoint;
    mbedtls_ecp_point_init(&testPoint);
    mbedtls_ecp_point_read_binary(&ctx_cli.grp, &testPoint, xbuff, x_len);


    //This tests that our new public key is equivalent to the old one, generates a shared secret
    mbedtls_ecdh_compute_shared( &ctx_cli.grp, &ctx_cli.z, &ctx_cli.Qp, &ctx_cli.d,
                                        mbedtls_ctr_drbg_random, &ctr_drbg );



    //Great! Now ctx_cli.z is a point representing the shared secret, it has it's own X and Y coords.
    char strz[512];
    size_t len;
    int stat = mbedtls_mpi_write_string(&ctx_cli.z, 10, strz, sizeof(strz), &len);
    if(stat != 0){
        printf("Stat not 0 while doing z!\n");
    }
    

    //Awesome! We now have our shared secret generated.
    //Need to perform symmetric encryption with this shared key
    int same = mbedtls_mpi_cmp_mpi( &ctx_cli.z, &ctx_srv.z );
    printf("Is the shared secret the same (0)? %d\n", same);
    printf("Shared secret is \n");
    for(int i = 0; i < (int)len; i++){
        printf("%c", strz[i]);
    }
    printf("\n");


    //AES Key generation part:
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    unsigned char key[32];
    memcpy(key, strz, 32);

    unsigned char iv1[16];
    unsigned char iv2[16];
    unsigned char input[128];
    unsigned char output[128];

    memcpy(input, "012345678901234567890123456789012345678", 39);

    mbedtls_aes_setkey_enc(&aes_ctx, key, 256);
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, 48, iv1, input, output);

    printf("\n");
    printf("printing input: ");
    for(int i = 0; i < 40; i++){
        printf("%c", input[i]);
    }
    printf("\n\n");
    printf("\n");
    printf("printing output: ");
    for(int i = 0; i < 48; i++){
        printf("%c", output[i]);
    }
    printf("\n\n\n");

    //In summary, this creates a shared key using ecdh, uses that key to create an AES key, and encrypts
    //this chunk of test. The encryption is not base64 encoded. 
    //Similarly, the output of the x and y 

    //Decrypting:
    unsigned char decrypted_output[128];
    mbedtls_aes_setkey_dec( &aes_ctx, key, 256 );
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, 48, iv2, output, decrypted_output);

    printf("printing decrypted output: ");
    for(int i = 0; i < 48; i++){
        printf("%c", decrypted_output[i]);
    }
    printf("\n");

return pub_key_buffer;

                      
}

mbedtls_ecdh_context gen_cli_ctx(){
    mbedtls_ecdh_context ctx_cli;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char pers[] = "ecdh";
    mbedtls_ecdh_init( &ctx_cli );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, sizeof pers );
    mbedtls_ecp_group_load( &ctx_cli.grp,     // Destination group
                                  ELLIPTIC_CURVE ); // Index in the list of well-known domain parameters

    mbedtls_ecdh_gen_public( &ctx_cli.grp,            // ECP group
                                &ctx_cli.d,              // Destination MPI (secret exponent, aka private key)
                                &ctx_cli.Q,              // Destination point (public key)
                                mbedtls_ctr_drbg_random, // RNG function
                                &ctr_drbg );             //RNG parameter
    return ctx_cli;
}

int pub_length(){
    return pub_key_len;
}
int ecc_keys(){
    yet_another();
    return 0;
}



struct ecc_public_key ecc_keys_get_pub(){
  return public;
}

struct ecc_private_key ecc_keys_get_priv(){
  return private;
}

int revamp(){
    printf("in revamp\n");
    struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key_cli, priv_key_srv;
	struct ecc_public_key pub_key_cli, pub_key_srv;
	int out_len, out_len2;


    ecc_mbedtls_init (&engine);

    //Uses NIST P-256
    engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key_cli, &pub_key_cli);
    engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key_srv, &pub_key_srv);

    //Process - generate two keys
    //Generate shared secret, be sure it's the same for both
    
    int shared1 = engine.base.get_shared_secret_max_length(&engine.base, &priv_key_cli);
    int shared2 = engine.base.get_shared_secret_max_length(&engine.base, &priv_key_srv);

	uint8_t out[shared1], out2[shared2];
    out_len = engine.base.compute_shared_secret (&engine.base, &priv_key_cli, &pub_key_srv, out, sizeof (out));
    out_len2 = engine.base.compute_shared_secret (&engine.base, &priv_key_srv, &pub_key_cli, out2, sizeof (out2));

    //Compare the shared secrets
    //Are the lengths the same
    if(out_len != out_len2){
        printf("ERROR : SHARED SECRETS ARE NOT THE SAME LENGTH");
    }
    for(int i = 0; i < out_len; i++){
        if(out[i] != out2[i]){
            printf("FALSE");
        }
    }

    //Now, encode the key into proper format using get_public_key_der

    uint8_t *pub_der = NULL;
    size_t der_length;
    engine.base.get_public_key_der (&engine.base, &pub_key_cli, &pub_der, &der_length);
        printf("length of der is %d and length of pub_der is %d", der_length, sizeof(pub_der));
    printf("DER IS %s\n\n\n\n", (const char*)pub_der);


    for(int i = 0; i < (int)der_length; i++){
        printf("%c", pub_der[i]);
    }




    return 0;
}