#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#ifdef INCLUDE_FFTW
#include <fftw3.h>
#endif

#define REAL 0
#define IMAG 1
#define BCM_MAX 1600
#define HEADER_LEN 80
int FFT_SIZE;

enum platform {
    BROADCOM,
    ATHEROS
};

enum platform board = BROADCOM;

int signedTwosComplementToSigned(unsigned char x) {
    return (x > 128 ? x - 256 : x);
}

int output_ath_fft_value(int16_t *out, int index, double rssi_add, int *min_dbm) {
    double value = (out[index] > 0) ? out[index] : 1;

    /* 10log10(Mj^2) */
    value = 10*log(pow(value, 2))/2.30;

    /* Add in rssi_dBM - 10log10(bin_sum_squares) */
    value += rssi_add;

    if ((int) value < *min_dbm)
        *min_dbm = (int) value;

    return (int) value;
}

#ifdef INCLUDE_FFTW
void output_bcm_fft_value(fftw_complex *out, int index, int bucketsize) {
    double value = 0;
    static int count = 0;
    static int max = -1000;
    //note log is actually ln

    // When there is no interference, the first sample is much larger than
    // it should be. Skip the sample, increment count to preserve buckets.
    if (index == 0) {
        count++;
        return;
    }

    //abs of a complex fft is magnitude of phasor.
    //converting to dB we do 20 * log
    //20 * log (sqrt(Re^2 + Imag^2)/N)
    //== 10 * log((Re^2 + Imag^2)/N^2)
    value = pow(out[index][REAL], 2) + pow(out[index][IMAG], 2);

    //divide by fftsize
    value = value / pow(FFT_SIZE, 2);

    //convert Vmag to dB
    value = 10 * log(value);

    //add in bandwidth since we are dBm / MHz
    if (FFT_SIZE == 800) {
        //10 * log (20)
        value = value + 29.96;
    } else {
        //10 * log (40)
        value = value + 36.89;
    }

    //bin size 0.05MHz/bin since we have 80MHz and 40MHz outputs from the FFT
    //10 * log (0.05)
    value = value + 29.96;

    //convert back to log base 10.
    //value / log(10)
    value = value / 2.30;

    //RF front end gain on topaz
    //-16.99 dBm -> subtract 10*log(1/50) (50ohm load)
    //+30 dBm -> convert from dBW to dBm
    //-68 dBm -> Broadcom RF guys as rf front end gain
    //           measured after the downconversion at the ADC.
    value = value -16.99 + 30 - 68;

    count++;
    if (value > max)
        max = value;

    if (count >= bucketsize) {
        printf("%d\n", max);
        max = -1000;
        count = 0;
    }
}
#endif //INCLUDE_FFTW

void printUsage(const char* name) {
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "%s OPTIONS < inputfile > outputfile\n", name);
    fprintf(stderr, "\nOPTIONS:\n");
    fprintf(stderr, "-b X    bin results into groups size X (last bin clipped)\n");
    fprintf(stderr, "-c X    choose which core (0 or 1)\n");
    fprintf(stderr, "-d      debug: print input data\n");
    fprintf(stderr, "-ath    run for atheros devices\n");
    fprintf(stderr, "-bcm    run for broadcom devices\n");
}

#ifdef INCLUDE_FFTW
void process_bcm_spectral(int bucketsize, int core, unsigned char input_data_dump) {
    fftw_complex *in = NULL;
    fftw_complex *out = NULL;
    fftw_plan p = NULL;
    unsigned char *i1 = NULL;
    unsigned char *i2 = NULL;
    unsigned char *q1 = NULL;
    unsigned char *q2 = NULL;
    unsigned char *header;
    int k = 0;
    FFT_SIZE = BCM_MAX;

    i1 = (unsigned char *)malloc(sizeof(unsigned char) * FFT_SIZE);
    q1 = (unsigned char *)malloc(sizeof(unsigned char) * FFT_SIZE);
    i2 = (unsigned char *)malloc(sizeof(unsigned char) * FFT_SIZE);
    q2 = (unsigned char *)malloc(sizeof(unsigned char) * FFT_SIZE);
    header = (unsigned char *)malloc(sizeof(unsigned char) * HEADER_LEN);
    if (!i1 || !q1 || !i2 || !q2) {
        printf("Failed to allocate buffers\n");
        goto bcm_exit;
    }

    //skip the 80 byte header
    scanf("%80c", header);
    //read I and Q values for each core
    while (!feof(stdin) && k < FFT_SIZE) {
            scanf("%c", &i1[k]);
            scanf("%c", &q1[k]);
            scanf("%c", &i2[k]);
            scanf("%c", &q2[k]);
            k++;
    }
    if (k < FFT_SIZE) {
        unsigned char *tmp;
        FFT_SIZE = k - 1;
        tmp = (unsigned char *)realloc(i1, sizeof(unsigned char) * FFT_SIZE);
        if (tmp) i1 = tmp;
        else goto bcm_exit;
        tmp = (unsigned char *)realloc(q1, sizeof(unsigned char) * FFT_SIZE);
        if (tmp) q1 = tmp;
        else goto bcm_exit;
        tmp = (unsigned char *)realloc(i2, sizeof(unsigned char) * FFT_SIZE);
        if (tmp) i2 = tmp;
        else goto bcm_exit;
        tmp = (unsigned char *)realloc(q2, sizeof(unsigned char) * FFT_SIZE);
        if (tmp) q2 = tmp;
        else goto bcm_exit;
    }

    // Allocate FFT buffers and plan
    in = (fftw_complex *)fftw_malloc(sizeof(fftw_complex) * FFT_SIZE);
    out = (fftw_complex *)fftw_malloc(sizeof(fftw_complex) * FFT_SIZE);
    if (!in || !out) {
        printf("Failed to allocate fftw structures\n");
        goto bcm_exit;
    }
    p = fftw_plan_dft_1d(FFT_SIZE, in, out, FFTW_FORWARD, FFTW_ESTIMATE);
    if (!p) {
        printf("Failed to create fftw plan\n");
        goto bcm_exit;
    }

    //Fill in FFT matrix
    for (k = 0; k < FFT_SIZE; k++) {
        if (core == 0) {
            //convert to Vrms
            //sample collect data is 8 MSB of 10 bit ADC
            //1111111100
            //so we multiply by 4
            //ADC is 0.8 V peak to peak / 10 bit (1024)
            in[k][REAL] = 4 * signedTwosComplementToSigned(i1[k]) * 0.8 / 1024;
            in[k][IMAG] = 4 * signedTwosComplementToSigned(q1[k]) * 0.8 / 1024;
        } else if (core == 1) {
            in[k][REAL] = 4 * signedTwosComplementToSigned(i2[k]) * 0.8 / 1024;
            in[k][IMAG] = 4 * signedTwosComplementToSigned(q2[k]) * 0.8 / 1024;
        }
    }

    /* If we are not dumping fft data
     * then we are trying to debug so
     * print the data we read in.
     */
    if (input_data_dump) {
        fprintf(stderr, "WARNING: debug dump\n");
        for (k = 0; k < FFT_SIZE; k++) {
            printf("%d\n", signedTwosComplementToSigned(i1[k]));
            printf("%d\n", signedTwosComplementToSigned(q1[k]));
            printf("%d\n", signedTwosComplementToSigned(i2[k]));
            printf("%d\n", signedTwosComplementToSigned(q2[k]));
        }
        goto bcm_exit;
    }

    fftw_execute(p);
    //Output executed plan to stdout
    //Remove the extra bandwidth and only keep the
    //real bandwidth (last 3/4 and first 1/4) which
    //gets shifted into the middle.
    for (k = FFT_SIZE / 4 * 3; k < FFT_SIZE; k++)
        output_bcm_fft_value(out, k, bucketsize);
    for (k = 0; k < FFT_SIZE / 4; k++)
        output_bcm_fft_value(out, k, bucketsize);

bcm_exit:
    if (i1) free(i1);
    if (q1) free(q1);
    if (i2) free(i2);
    if (q2) free(q2);
    if (header) free(header);
    if (p) fftw_destroy_plan(p);
    if (in) fftw_free(in);
    if (out) fftw_free(out);
}
#endif //INCLUDE_FFTW

void process_ath_spectral(int bucketsize, unsigned char input_data_dump, char * model, int channel) {
    int16_t *data = NULL;
    int16_t rssi_dBm;
    int16_t rssi;
    int16_t noise_floor;
    int16_t num_samples;
    double rssi_add;
    int32_t bin_sum_squares = 0;
    int k = 0;
    int min_dbm = 10000;
    int nf_2ghz_adjust = 38;
    int nf_5ghz_adjust = 45;
    int nf_default_adjust = nf_2ghz_adjust;

    /* First int is bin size */
    scanf("%2c", &num_samples);

    data = (int16_t *)malloc(sizeof(int16_t) * num_samples);
    if (!data) {
        printf("Failed to allocate data buffer\n");
        return;
    }

    /* Second int is Rssi as SNR to convert to dBm add noise floor */
    scanf("%2c", &rssi);

    scanf("%2c", &noise_floor);

    /* Convert from SNR-margin to rssi */
    rssi_dBm = rssi + noise_floor;

    while (!feof(stdin) && k < num_samples) {
        scanf("%2c", &data[k++]);
    }

    /* Find the sum of the squares of the
     * magnitudes of all the bins
     */
    for (k = 0; k < num_samples; k++) {
       bin_sum_squares += pow(data[k], 2);
    }

    /* If we are not dumping fft data
     * then we are trying to debug so
     * print the data we read in.
     */
    if (input_data_dump) {
        fprintf(stderr, "WARNING: debug dump\n");
        for (k = 0; k < num_samples; k++) {
            fprintf(stderr, "%d ", data[k]);
        }
	fprintf(stderr, "\n");
    }

    /* The simplified formula for the power per bin is:
     * RSSI_per_bin_j_dbm = RSSI_dBm + 10log10(Mj^2) - 10log10(bin_sum_squares)
     * Only the 10log10(Mj^2) part is dependant on bin
     * so simplify the rest down to one factor
     */
    rssi_add = rssi_dBm - (10*log(bin_sum_squares)/2.30);

    /* Convert linear data to dBm and save back in array */
    for (k = 0; k < num_samples; k++) {
        data[k] = output_ath_fft_value(data, k, rssi_add, &min_dbm);
    }

    /* Print data shifted to a noise floor of -96 */
    for (k = 0; k < num_samples; k++) {
        if (model && (strcmp(model, "MR42") == 0)) {
            printf("%d\n", data[k] + (-96) - min_dbm);
        } else {
            int adjust = (channel == 0) ? nf_default_adjust : (channel > 14) ? nf_5ghz_adjust : nf_2ghz_adjust;
            printf("%d\n", data[k] + adjust);
        }
    }

    if (data) free(data);
}

int main(int argc, char *argv[]) {
    int i = 0;
    int bucketsize = 1;
    int core = 0;
    unsigned char input_data_dump = 0;
    int channel = 0;
    char * model = NULL;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-b")) {
            i++;
            bucketsize = atoi(argv[i]);
            if (bucketsize < 0 || bucketsize > BCM_MAX / 10) {
                bucketsize = 1;
            }
        } else if (!strcmp(argv[i], "-c")) {
            i++;
            core = atoi(argv[i]);
            if (core < 0 || core > 1) {
                core = 0;
            }
        } else if (!strcmp(argv[i], "-n")) {
            int val = 0;
            i++;
            val = atoi(argv[i]);
            if (val == 3280) {
                FFT_SIZE = 800;
            } else if (val == 6480) {
                FFT_SIZE = 1600;
            }
        } else if (!strcmp(argv[i], "-m")) {
            model = argv[++i];
        } else if (!strcmp(argv[i], "-d")) {
            input_data_dump = 1;
        } else if (!strcmp(argv[i], "--chan")) {
            channel = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--bcm")) {
            board = BROADCOM;
        } else if (!strcmp(argv[i], "--ath")) {
            board = ATHEROS;
        } else if (!strncmp(argv[i], "-", 1)) {
            printUsage(argv[0]);
            exit(-1);
        }
    }

    if (board == ATHEROS)
        process_ath_spectral(bucketsize, input_data_dump, model, channel);
#ifdef INCLUDE_FFTW
    else if (board == BROADCOM)
        process_bcm_spectral(bucketsize, core, input_data_dump);
#endif
    else
        printf("Error: No board selected\n");

    return 0;
}
