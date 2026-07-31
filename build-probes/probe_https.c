// Minimal 32-bit HTTPS fetch to isolate Steam's "http error 0" from
// its own httplib. If this succeeds, the FEX 32-bit network path is
// fine and Steam is failing for a Steam-specific reason. If this
// fails, the defect is under FEX -- probably somewhere in
// send/recv/poll/OpenSSL under i386.
//
// Usage: probe_https [URL]
//   Default URL: https://client-update.steamstatic.com/steam_client_ubuntu12
//   (the URL Steam itself fails on)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

static size_t sink(void* p, size_t sz, size_t n, void* ud) {
  size_t* total = (size_t*)ud;
  *total += sz * n;
  return sz * n;
}

int main(int argc, char** argv) {
  const char* url = argc > 1 ? argv[1]
                             : "https://client-update.steamstatic.com/steam_client_ubuntu12";

  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURL* c = curl_easy_init();
  if (!c) { fprintf(stderr, "curl_easy_init failed\n"); return 1; }

  size_t total = 0;
  char errbuf[CURL_ERROR_SIZE] = {0};

  curl_easy_setopt(c, CURLOPT_URL, url);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, sink);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &total);
  curl_easy_setopt(c, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
  curl_easy_setopt(c, CURLOPT_VERBOSE, 0L);
  curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);

  CURLcode rc = curl_easy_perform(c);
  long http_code = 0;
  curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &http_code);
  double dl_speed = 0, dl_time = 0;
  curl_easy_getinfo(c, CURLINFO_SPEED_DOWNLOAD, &dl_speed);
  curl_easy_getinfo(c, CURLINFO_TOTAL_TIME, &dl_time);

  printf("URL:          %s\n", url);
  printf("rc:           %d (%s)\n", (int)rc, curl_easy_strerror(rc));
  printf("http_code:    %ld\n", http_code);
  printf("bytes_recvd:  %zu\n", total);
  printf("wall_time:    %.3f s\n", dl_time);
  printf("dl_speed:     %.0f B/s\n", dl_speed);
  if (errbuf[0]) printf("errbuf:       %s\n", errbuf);

  curl_easy_cleanup(c);
  curl_global_cleanup();
  return rc == CURLE_OK ? 0 : 2;
}
