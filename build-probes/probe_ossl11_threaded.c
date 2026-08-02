// SPDX-License-Identifier: MIT
//
// E4 — threaded variant of probe_ossl11.c. Same SSL_connect against
// Debian's libssl1.1_1.1.1i-3, but the whole handshake runs on a
// spawned pthread while main just joins. Previous i386-TLS-under-FEX
// probes all ran on the main thread; that matched the "controlled"
// case but not what Steam's manifest fetch actually does.
//
// If 32-bit threaded fails where main-thread passes → minimal
// open-source repro for Steam and a lead on the thread-corruption
// bug. If both pass at 30+ runs → threading isn't the differentiator
// and Steam goes back on the shelf for good.
//
// Build (same as probe_ossl11.c, plus -lpthread):
//   clang -m32 --target=i386-linux-gnu -fuse-ld=lld \
//     --sysroot=$ROOTFS -I$ROOTFS/usr/include \
//     -Wl,-dynamic-linker=/lib/ld-linux.so.2 \
//     build-probes/probe_ossl11_threaded.c \
//     /tmp/ossl11/extracted/usr/lib/i386-linux-gnu/libssl.so.1.1 \
//     /tmp/ossl11/extracted/usr/lib/i386-linux-gnu/libcrypto.so.1.1 \
//     -Wl,-rpath=/tmp/ossl11/extracted/usr/lib/i386-linux-gnu \
//     -lpthread \
//     -o build-probes/probe_ossl11_threaded_32
//
// Usage: probe_ossl11_threaded_32 <host> <port> [max_version]
// Exit codes:
//   0  = handshake success
//   1  = SSL_CTX_new failure
//   2  = TCP connect failure
//   3  = SSL_connect failure
//   4  = pthread_create/join failure

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

struct HandshakeArgs {
  const char* host;
  const char* port;
  int max_ver;
  int rc;         // exit code the thread wants main to return
};

static int tcp_connect(const char* host, const char* port) {
  struct addrinfo hints = {0}, *res = NULL;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  int gerr = getaddrinfo(host, port, &hints, &res);
  if (gerr != 0) {
    fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(gerr));
    return -1;
  }
  int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (fd < 0) { perror("socket"); freeaddrinfo(res); return -1; }
  if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
    perror("connect");
    close(fd);
    freeaddrinfo(res);
    return -1;
  }
  freeaddrinfo(res);
  return fd;
}

static void* handshake_thread(void* arg) {
  struct HandshakeArgs* args = arg;

  SSL_load_error_strings();
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

  const SSL_METHOD* method = TLS_client_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (!ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); args->rc = 1; return NULL; }

  SSL_CTX_set_default_verify_paths(ctx);
  SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs");

  if (args->max_ver == 12) {
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
  }
  if (getenv("FORCE_HRR")) {
    SSL_CTX_set1_groups_list(ctx, "P-521:P-384:P-256");
  }

  int fd = tcp_connect(args->host, args->port);
  if (fd < 0) { SSL_CTX_free(ctx); args->rc = 2; return NULL; }

  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
  SSL_set_tlsext_host_name(ssl, args->host);

  int rc = SSL_connect(ssl);
  int ssl_err = SSL_get_error(ssl, rc);

  printf("SSL_connect rc=%d ssl_err=%d\n", rc, ssl_err);
  if (rc <= 0) {
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
      char buf[256];
      ERR_error_string_n(e, buf, sizeof(buf));
      printf("  err: %s\n", buf);
    }
    args->rc = 3;
  } else {
    printf("negotiated: %s / %s\n", SSL_get_version(ssl), SSL_get_cipher(ssl));
    args->rc = 0;
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(fd);
  SSL_CTX_free(ctx);
  return NULL;
}

int main(int argc, char** argv) {
  struct HandshakeArgs args = {
    .host    = argc > 1 ? argv[1] : "client-update.steamstatic.com",
    .port    = argc > 2 ? argv[2] : "443",
    .max_ver = argc > 3 ? atoi(argv[3]) : 0,
    .rc      = 4,
  };

  printf("openssl: %s\n", OpenSSL_version(OPENSSL_VERSION));
  printf("target:  %s:%s%s (handshake on spawned pthread)\n\n",
         args.host, args.port,
         args.max_ver == 12 ? " (max TLS 1.2)" : "");

  pthread_t tid;
  int err = pthread_create(&tid, NULL, handshake_thread, &args);
  if (err) {
    fprintf(stderr, "pthread_create: %s\n", strerror(err));
    return 4;
  }

  void* ret;
  err = pthread_join(tid, &ret);
  if (err) {
    fprintf(stderr, "pthread_join: %s\n", strerror(err));
    return 4;
  }

  return args.rc;
}
