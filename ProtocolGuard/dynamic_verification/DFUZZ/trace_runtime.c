/* Standalone instrumentation runtime: bounded trace, exclusive output file. */
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdatomic.h>
static int fd = -2;
static unsigned count = 0;
static atomic_flag lock = ATOMIC_FLAG_INIT;
void __pg_visit(unsigned block, int distance) {
  while (atomic_flag_test_and_set_explicit(&lock, memory_order_acquire)) {}
  if (fd == -2) {
    const char *path = getenv("PG_DIRECTED_TRACE");
    if (!path) _exit(120);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) _exit(121);
  }
  if (count++ >= 100000) { atomic_flag_clear_explicit(&lock, memory_order_release); return; }
  char buffer[96];
  int size = snprintf(buffer, sizeof(buffer), "%u %d\n", block, distance);
  if (write(fd, buffer, (size_t)size) != size) _exit(122);
  atomic_flag_clear_explicit(&lock, memory_order_release);
}
