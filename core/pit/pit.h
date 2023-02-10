#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

/**
 * Sets up needed variables and sets the systems state to lock.
 * Exchanges keys with the server to create a secret key
 * @param secret A 32-byte empty array which will be loaded with the shared secret
 * @return 1 on success
*/
int lock(uint8_t *secret);

/**
 * Unlocks the state of the machine by validating OTP
 * Creates an OTP, then encrypts it as OTPs. Sends OTPs to the server.
 * Server then encrypts OTPs again, then sends it back to the client.
 * Client decrypts server's message and validates OTPs against original OTP
 * @return 1 on success
*/
int unlock();

/** Gets the state of the system
 * @return The numerical value of the state of the system at the moment of calling
*/
int get_state();

/**
 * Get the encrypted OTP (OTPs) from the system
 * @param OTPs Empty buffer to hold the encrypted OTP into
 * @return 1 on success
*/
int get_OTPs(uint8_t *OTPs);