#ifndef COMPRESS_H
#define COMPRESS_H

#include <linux/crypto.h>

#define COMPRESS_ALGORITHM "deflate"

bool compress(const char *input,
              unsigned int input_len,
              char *output,
              unsigned int *output_len);

#endif