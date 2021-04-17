#include <ar.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/md5.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FLAG_PRINT_HEADER 0x1
#define FLAG_TAIL_PADDING 0x2

typedef struct _hdr_list_t {
  struct ar_hdr hdr;
  struct _hdr_list_t *next;
  uint8_t md5[MD5_DIGEST_LENGTH];
} hdr_list_t;

static _Noreturn void usage(const char *execname) {
  printf("Usage: %s [-h] [-p] [archive file]\n", execname);
  exit(EXIT_SUCCESS);
}

static void copy_hash_data(uint8_t *dest, FILE *fp, size_t n) {
  assert(dest && fp && "Invalid file pointer.");
  uint8_t *buf = malloc(n);
  if (!buf) {
    fprintf(stderr, "Error allocating data buffer.\n");
    exit(EXIT_FAILURE);
  }
  const long pos = ftell(fp);
  if (fread(buf, 1, n, fp) != n) {
    fprintf(stderr, "Error reading data.\n");
    exit(EXIT_FAILURE);
  }

  if (MD5(buf, n, (unsigned char *)dest) == 0) {
    fprintf(stderr, "Error calculating MD5 hash.\n");
    exit(EXIT_FAILURE);
  }
  fseek(fp, pos, SEEK_SET);
  free(buf);
}

static void reverse_list(hdr_list_t **list) {
  hdr_list_t *node = *list, *prev = NULL;
  while (node) {
    hdr_list_t *temp = node->next;
    node->next = prev;
    prev = node;
    node = temp;
  }
  *list = prev;
}

static void print(bool print_header, const char *fname, const hdr_list_t *hdr) {
  if (print_header) printf("file,object,date,uid,gid,mode,size,md5\n");
  for (const hdr_list_t *node = hdr; node; node = node->next) {
    printf("%s,%s,%s,%s,%s,%s,%s,", fname, node->hdr.ar_name, node->hdr.ar_date,
           node->hdr.ar_uid, node->hdr.ar_gid, node->hdr.ar_mode,
           node->hdr.ar_size);
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) printf("%02x", node->md5[i]);
    putc('\n', stdout);
  }
}

static long file_size(FILE *fp) {
  const long cur = ftell(fp);
  fseek(fp, 0, SEEK_END);
  const long end = ftell(fp);
  fseek(fp, cur, SEEK_SET);
  return end;
}

static void sanitize_string(char *str, size_t max) {
  assert(str && "Invalid input.");
  size_t i = 0;
  while (i < max) {
    if (str[i] == 0)
      break;
    else if (!isprint(str[i]))
      str[i] = '?';
    ++i;
  }
}

static void sanitize(struct ar_hdr *hdr) {
  assert(hdr && "Invalid input.");
  sanitize_string(hdr->ar_name, sizeof(hdr->ar_name));
  sanitize_string(hdr->ar_date, sizeof(hdr->ar_date));
  sanitize_string(hdr->ar_uid, sizeof(hdr->ar_uid));
  sanitize_string(hdr->ar_gid, sizeof(hdr->ar_gid));
  sanitize_string(hdr->ar_mode, sizeof(hdr->ar_mode));
  sanitize_string(hdr->ar_size, sizeof(hdr->ar_size));
}

static hdr_list_t *parse(FILE *fp, int flags, long *bytes_to_end) {
  assert(fp && bytes_to_end && "Invalid input.");
  struct stat st;
  fstat(fileno(fp), &st);
  if ((st.st_mode & S_IFMT) == S_IFLNK) {
    fprintf(stderr,
            "symlinks are not supported, please specify the path to the "
            "archive.\n");
    exit(EXIT_FAILURE);
  }

  char magic[SARMAG] = {0};
  if ((fread(&magic, 1, SARMAG, fp) != SARMAG) ||
      (strncmp(ARMAG, magic, SARMAG) != 0)) {
    fprintf(stderr, "Error reading magic number.\n");
    exit(EXIT_FAILURE);
  }

  hdr_list_t *head = NULL;
  struct ar_hdr hdr;
  const long end = file_size(fp);
  while (fread(&hdr, 1, sizeof(struct ar_hdr), fp) == sizeof(struct ar_hdr)) {
    hdr.ar_name[sizeof(hdr.ar_name) - 1] = '\0';
    hdr.ar_date[sizeof(hdr.ar_date) - 1] = '\0';
    hdr.ar_uid[sizeof(hdr.ar_uid) - 1] = '\0';
    hdr.ar_gid[sizeof(hdr.ar_gid) - 1] = '\0';
    hdr.ar_mode[sizeof(hdr.ar_mode) - 1] = '\0';
    hdr.ar_size[sizeof(hdr.ar_size) - 1] = '\0';
    sanitize(&hdr);
    const long size = atol(hdr.ar_size);
    hdr_list_t *hdrp = calloc(1, sizeof(hdr_list_t));
    if (!hdrp) {
      fprintf(stderr, "Error allocating header memory.\n");
      exit(EXIT_FAILURE);
    }
    memcpy(&hdrp->hdr, &hdr, sizeof(struct ar_hdr));
    copy_hash_data(hdrp->md5, fp, size);
    hdrp->next = head;
    head = hdrp;
    fseek(fp, size, SEEK_CUR);
    *bytes_to_end = end - ftell(fp);
  }
  reverse_list(&head);
  return head;
}

int main(int argc, char **argv) {
  int opt, flags = 0;
  const char *fname = NULL;
  if (argc == 1) usage(argv[0]);
  while ((opt = getopt(argc, argv, "hp")) != -1) {
    switch (opt) {
      case 'h':
        flags |= FLAG_PRINT_HEADER;
        print(true, NULL, NULL);
        break;
      case 'p':
        flags |= FLAG_TAIL_PADDING;
        break;
      case '?':
      default:
        usage(argv[0]);
    }
  }

  // Get the filename of the archive.
  fname = argv[optind];
  FILE *fp = fopen(fname, "r");
  if (!fp && (flags & FLAG_PRINT_HEADER))
    exit(EXIT_SUCCESS);
  else if (!fp) {
    fprintf(stderr, "Error opening %s: %s\n", fname, strerror(errno));
    exit(EXIT_FAILURE);
  }

  // Analyze the archive.
  long bytes_to_end = 0;
  const hdr_list_t *list = parse(fp, flags, &bytes_to_end);
  print(false, fname, list);
  if (flags & FLAG_TAIL_PADDING)
    printf("Tail padding: %zu bytes\n", bytes_to_end);

  fclose(fp);
  return 0;
}
