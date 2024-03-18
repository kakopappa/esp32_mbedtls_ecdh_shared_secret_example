
class ECDH {
private:
  mbedtls_ecdh_context ctx;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

public:
  static const size_t KEY_SIZE = 32;

  ECDH() {
    mbedtls_ecdh_init(&ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
  }

  ~ECDH() {
    mbedtls_ecdh_free(&ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
  }

  void generateKeys(unsigned char* pubkey, unsigned char* privkey) {
    unsigned char l_pubkey[KEY_SIZE] = { 0 };
    unsigned char l_privkey[KEY_SIZE] = { 0 };

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 0, 0);
    mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_CURVE25519);
    mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_mpi_write_binary_le(&ctx.Q.X, l_pubkey, sizeof(l_pubkey));
    mbedtls_mpi_write_binary_le(&ctx.d, l_privkey, sizeof(l_privkey));

    memcpy(pubkey, l_pubkey, sizeof(l_pubkey));
    memcpy(privkey, l_privkey, sizeof(l_privkey)); 
  }

  int calculateSecret(unsigned char* privkey, unsigned char* serverpubkey, unsigned char* sharedsecret) {
    unsigned char my_privkey[KEY_SIZE] = { 0 };
    unsigned char server_pubkey[KEY_SIZE] = { 0 };
    unsigned char shared_secret[KEY_SIZE] = { 0 };
    unsigned char buffer[KEY_SIZE] = { 0 };
    
    memcpy(my_privkey, privkey, KEY_SIZE);
    memcpy(server_pubkey, serverpubkey, KEY_SIZE);

    int ret = 1;
   
    mbedtls_ctr_drbg_seed(
      &ctr_drbg,
      mbedtls_entropy_func,
      &entropy,
      0,
      0);

    ret = mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_CURVE25519);

    if (ret != 0) {
      return ret;
    }

    // read my private key
    ret = mbedtls_mpi_read_binary_le(&ctx.d, my_privkey, sizeof(my_privkey));
    if (ret != 0) {
      return ret;
    }

    ret = mbedtls_mpi_lset(&ctx.Qp.Z, 1);
    if (ret != 0) {
      return ret;
    }

    // read server key
    ret = mbedtls_mpi_read_binary_le(&ctx.Qp.X, server_pubkey, sizeof(server_pubkey));
    if (ret != 0) {
      return ret;
    }

    //generate shared secret
    size_t olen;
    ret = mbedtls_ecdh_calc_secret(&ctx, &olen, shared_secret, 32, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
      char error_buf[100];
      mbedtls_strerror(ret, error_buf, sizeof(error_buf));
      printf("mbedtls_ecdh_calc_secret error code %d: %s\n", ret, error_buf);
      return ret;
    }

    mbedtls_mpi_write_binary_le(&ctx.z, buffer, sizeof(buffer));
    memcpy(sharedsecret, shared_secret, sizeof(shared_secret)); 
    return ret;
  }
};
