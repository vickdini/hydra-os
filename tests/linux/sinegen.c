/* sinegen OUT SECONDS: a 440 Hz stereo 16-bit 48 kHz sine as a WAV file (Group 25 sound test). */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
static void w32(FILE *f, uint32_t v) { fwrite(&v, 4, 1, f); }
static void w16(FILE *f, uint16_t v) { fwrite(&v, 2, 1, f); }
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    FILE *f = fopen(argv[1], "wb");
    if (!f) return 1;
    uint32_t n = 48000u * atoi(argv[2]);
    fwrite("RIFF", 1, 4, f); w32(f, 36 + n * 4); fwrite("WAVEfmt ", 1, 8, f);
    w32(f, 16); w16(f, 1); w16(f, 2); w32(f, 48000); w32(f, 48000 * 4); w16(f, 4); w16(f, 16);
    fwrite("data", 1, 4, f); w32(f, n * 4);
    for (uint32_t i = 0; i < n; i++) {
        int16_t s = (int16_t)(12000.0 * sin(2 * M_PI * 440.0 * i / 48000.0));
        w16(f, s); w16(f, s);
    }
    fclose(f);
    return 0;
}
