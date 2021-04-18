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
  char name[1 + sizeof(((struct ar_hdr *)0)->ar_name)];
  uint64_t date;  // See ar.h ar_date.
  uint32_t uid;   // See ar.h ar_uid.
  uint32_t gid;   // See ar.h ar_gid.
  uint32_t mode;  // See ar.h ar_mode. (octal)
  uint64_t size;  // See ar.h ar_size. (octal)
  uint8_t md5[MD5_DIGEST_LENGTH];
  struct _hdr_list_t *next;
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

// Output each object within the archive as a comma separated value row.
static void print(bool print_header, const char *fname, const hdr_list_t *hdr) {
  if (print_header) printf("file,object,date,uid,gid,mode,size,md5\n");
  for (const hdr_list_t *node = hdr; node; node = node->next) {
    printf("%s,%s,%lu,%u,%u,%o,%lu,", fname, node->name, node->date, node->uid,
           node->gid, node->mode, node->size);
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

static uint64_t safe_strtou(const char *str, size_t length, unsigned base,
                            bool is_u64) {
  assert(str && "Invalid input.");
  char buf[32] = {0};
  if (length >= sizeof(buf)) abort();
  memcpy(buf, str, length);
  return (is_u64) ? strtoull(buf, NULL, base) : strtoul(buf, NULL, base);
}

// Remove commas and truncate the string when a non-printable is discovered.
static void sanitize(char *str, size_t length) {
  assert(str && "Invalid input.");
  for (size_t i = 0; i < length; ++i)
    if (str[i] == 0)
      break;
    else if (!isprint(str[i])) {
      str[i] = '\0';
      break;
    } else if (str[i] == ',')
      str[i] = '?';
}

// Generate a list of the objects within an archive file.
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
    fprintf(stderr, "Error: This is not an archive file.\n");
    exit(EXIT_FAILURE);
  }

  hdr_list_t *head = NULL;
  struct ar_hdr hdr;
  const long end = file_size(fp);
  while (fread(&hdr, 1, sizeof(struct ar_hdr), fp) == sizeof(struct ar_hdr)) {
    const long size = atol(hdr.ar_size);
    hdr_list_t *h = calloc(1, sizeof(hdr_list_t));
    if (!h) {
      fprintf(stderr, "Error allocating header memory.\n");
      exit(EXIT_FAILURE);
    }
    // hdrp->name is 1 byte more than hdr.ar_name; thus, always null terminated.
    sanitize(hdr.ar_name, sizeof(hdr.ar_name));
    strncpy(h->name, hdr.ar_name, sizeof(h->name) - 1);
    h->date = safe_strtou(hdr.ar_date, sizeof(hdr.ar_date), 10, true);
    h->uid = (uint32_t)safe_strtou(hdr.ar_uid, sizeof(hdr.ar_uid), 10, false);
    h->gid = (uint32_t)safe_strtou(hdr.ar_gid, sizeof(hdr.ar_gid), 10, false);
    h->mode = (uint32_t)safe_strtou(hdr.ar_mode, sizeof(hdr.ar_mode), 8, false);
    h->size = safe_strtou(hdr.ar_size, sizeof(hdr.ar_size), 10, true);
    copy_hash_data(h->md5, fp, size);
    h->next = head;
    head = h;
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
