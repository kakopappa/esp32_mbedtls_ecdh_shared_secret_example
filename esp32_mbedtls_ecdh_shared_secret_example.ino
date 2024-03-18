#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "mbedtls/error.h"

#include "ECDH.h"
 
 
void setup() {
  Serial.begin(115200);
  // put your setup code here, to run once:

  ECDH client;

  unsigned char my_pubkey[ECDH::KEY_SIZE] = {0};
  unsigned char my_privkey[ECDH::KEY_SIZE] = {0};

  unsigned char server_pubkey[ECDH::KEY_SIZE] = {0};
  unsigned char server_privkey[ECDH::KEY_SIZE] = {0};

  unsigned char shared_secret[ECDH::KEY_SIZE] = {0};
  unsigned char shared_secret2[ECDH::KEY_SIZE] = {0};

  client.generateKeys(my_pubkey, my_privkey);
  
  Serial.printf("my_pubkey: ");
  for (size_t i = 0; i < sizeof(my_pubkey); i++)
    Serial.printf("%02x", my_pubkey[i]);
  Serial.printf("\n"); 

  Serial.printf("my_privkey: ");
  for (size_t i = 0; i < sizeof(my_privkey); i++)
    Serial.printf("%02x", my_privkey[i]);
  Serial.printf("\n"); 

  Serial.printf("\n"); 
  
  ECDH server;

  server.generateKeys(server_pubkey, server_privkey);
  Serial.printf("server_pubkey: ");
  for (size_t i = 0; i < sizeof(server_pubkey); i++)
    Serial.printf("%02x", server_pubkey[i]);
  Serial.printf("\n"); 

  Serial.printf("server_privkey: ");
  for (size_t i = 0; i < sizeof(server_privkey); i++)
    Serial.printf("%02x", server_privkey[i]);
  Serial.printf("\n"); Serial.printf("\n");

  client.calculateSecret(my_privkey, server_pubkey, shared_secret);

  Serial.printf("Secret        :");
  for (size_t i = 0; i < sizeof(shared_secret); i++)
    Serial.printf("%02X", shared_secret[i]);
  Serial.printf("\n");
  
  server.calculateSecret(server_privkey, my_pubkey, shared_secret2);
  
  Serial.printf("Server Secret :");
  for (size_t i = 0; i < sizeof(shared_secret2); i++)
    Serial.printf("%02X", shared_secret2[i]);
}

void loop() {
  // put your main code here, to run repeatedly:
}