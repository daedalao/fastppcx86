// Minimal 32-bit OpenSSL-1.1.1i reproducer for the Steam-under-FEX
// alert-70 defect. Uses the OpenSSL 1.1 dynamic libraries extracted
// from Debian's `libssl1.1_1.1.1i-3_i386.deb` (matching Steam's
// bundled version exactly).
//
// The distinguishing test: point at
//   (1) Steam CDN (fails Steam)
//   (2) Cloudflare (TLS 1.3, common)
//   (3) A TLS 1.2-only endpoint (control -- if this fails too, the
//       library is broken under emulation more generally)
//
// Build:
//   clang -m32 --target=i386-linux-gnu -fuse-ld=lld \
//     --sysroot=$ROOTFS \
//     -I<ossl11 headers> \
//     build-probes/probe_ossl11.c \
//     /tmp/ossl11/extracted/usr/lib/i386-linux-gnu/libssl.so.1.1 \
//     /tmp/ossl11/extracted/usr/lib/i386-linux-gnu/libcrypto.so.1.1 \
//     -Wl,-rpath=/tmp/ossl11/extracted/usr/lib/i386-linux-gnu \
//     -o build-probes/probe_ossl11
//
// Usage:
//   probe_ossl11 <host> <port> [max_version]
//     max_version = 12 forces TLS 1.2 (SSL_CTX_set_max_proto_version)
//     Otherwise defaults to library default (up to TLS 1.3).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

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

int main(int argc, char** argv) {
  const char* host = argc > 1 ? argv[1] : "client-update.steamstatic.com";
  const char* port = argc > 2 ? argv[2] : "443";
  int max_ver = argc > 3 ? atoi(argv[3]) : 0;

  printf("openssl: %s\n", OpenSSL_version(OPENSSL_VERSION));
  printf("target:  %s:%s%s\n\n", host, port,
         max_ver == 12 ? " (max TLS 1.2)" : "");

  SSL_load_error_strings();
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

  const SSL_METHOD* method = TLS_client_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (!ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); return 1; }

  // Load default CA store. Try /etc/ssl/certs first (Debian layout),
  // then let OpenSSL fall through to compile-time defaults.
  SSL_CTX_set_default_verify_paths(ctx);
  SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt",
                                     "/etc/ssl/certs");

  if (max_ver == 12) {
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
  }

  // If FORCE_HRR is set, mimic Steam's key_share behaviour: offer
  // supported_groups {P-521, P-384, P-256} but a key_share only for
  // P-521. Server will HRR asking for P-384.
  if (getenv("FORCE_HRR")) {
    SSL_CTX_set1_groups_list(ctx, "P-521:P-384:P-256");
  }

  int fd = tcp_connect(host, port);
  if (fd < 0) { SSL_CTX_free(ctx); return 2; }

  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
  SSL_set_tlsext_host_name(ssl, host);

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
  } else {
    printf("negotiated: %s / %s\n", SSL_get_version(ssl),
           SSL_get_cipher(ssl));

    // Send a HEAD request and read a bit of response
    char req[512];
    snprintf(req, sizeof(req),
             "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    SSL_write(ssl, req, strlen(req));
    char buf[1024] = {0};
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n > 0) {
      // Print just status line
      char* nl = strchr(buf, '\n');
      if (nl) *nl = 0;
      printf("status: %s\n", buf);
    }
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(fd);
  SSL_CTX_free(ctx);
  return rc <= 0 ? 3 : 0;
}
