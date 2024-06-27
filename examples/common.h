#ifndef COMMON_H
#define COMMON_H

#ifdef MICROBENCHMARK
#define debug_printf(...) (0)
#define MICROBENCHMARK_LOOP_START for (int i = 0; i < 50000; i++) {
#define MICROBENCHMARK_LOOP_END   }
#else
#define debug_printf(...) printf(__VA_ARGS__)
#define MICROBENCHMARK_LOOP_START
#define MICROBENCHMARK_LOOP_END
#endif

#endif //COMMON_H
