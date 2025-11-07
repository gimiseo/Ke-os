// 17.14 fixed-point number representation
#define F (1 << 14)

#ifndef int64_t
#include <stdint.h>
#endif

// Convert n to fixed point
int int_to_fp (int n) {
  return n * F;
}

// Convert x to integer (rounding toward zero)
int fp_to_int_round_zero (int x) {
  return x / F;
}

// Convert x to integer (rounding to nearest)
int fp_to_int_round_near (int x) {
  if (x >= 0)
    return (x + F / 2) / F;
  return (x - F / 2) / F;
}

// Add x and y
int add_fp (int x, int y) {
  return x + y;
}

// Subtract y from x
int sub_fp (int x, int y) {
  return x - y;
}

// Add x and n
int add_fp_int (int x, int n) {
  return x + n * F;
}

// Subtract n from x
int sub_fp_int (int x, int n) {
  return x - n * F;
}

// Multiply x by y
int mul_fp (int x, int y) {
  return ((int64_t) x) * y / F;
}

// Multiply x by n
int mul_fp_int (int x, int n) {
  return x * n;
}

// Divide x by y
int div_fp (int x, int y) {
  return ((int64_t) x) * F / y;
}

// Divide x by n
int div_fp_int (int x, int n) {
  return x / n;
}