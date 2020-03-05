/*
 *   __  __       _   _               _____       _            _
 *  |  \/  |     | | (_)             |  __ \     | |          | |
 *  | \  / | ___ | |_ _  ___  _ __   | |  | | ___| |_ ___  ___| |_ ___  _ __
 *  | |\/| |/ _ \| __| |/ _ \| '_ \  | |  | |/ _ \ __/ _ \/ __| __/ _ \| '__|
 *  | |  | | (_) | |_| | (_) | | | | | |__| |  __/ ||  __/ (__| || (_) | |
 *  |_|  |_|\___/ \__|_|\___/|_| |_| |_____/ \___|\__\___|\___|\__\___/|_|
 *
 *
 * Author: Nat Storer <n@meraki.com>
 * Date: 5/12/2016
 * Info: This program analyzes a video clip and reports a list of macroblocks
 *       which contained significant motion. When compiled outside of the
 *       camera build system, it will display the video and visualize motion.
 *
 * == What is this? ==
 *
 * This program is designed so that it can be built into the camera firmware
 * as an openwrt package, but can also be run on a development machine to test
 * and tune the filtering algorithms.
 *
 * To run this program on your development machine, you will need to install
 * both ffmpeg and opencv, then copy motiondetector.cc and CMakeLists.txt to a
 * new directory. "cmake ." should set up the build system, and "make" will
 * build the executable.
 *
 * == How it works ==
 *
 * First, the detector decodes the video. The majority of this code was
 * inspired by one of the ffmpeg sample programs, extract_mvs, which extracts
 * H264 motion vectors.
 *
 * As the detector decodes frames, it compares the current frame to the last
 * one. For each H264 Macroblock (16 x 16 px), it computes the sum of absolute
 * differences between the two frames (an average of the Y, U, and V planes).
 *
 *   Note: In the YUV semi-planar format, the U and V planes are smaller
 *         than the Y plane. As such, the U and V values are scaled so that
 *         they are weighted equally.
 *
 * If this YUV SAD average for a macroblock is above a certain threshold, it
 * is considered to be significant motion.
 *
 * == Filtering ==
 *
 * Once the whole frame has been processed, a simple spatial filter is applied.
 * If a macroblock with motion has no immediate neighbors with motion (N / S / E
 * / W, no diaganals), it is discarded. The macroblocks which remain after this
 * filter are added to an aggregate list of motion blocks, which stores each of
 * the blocks affected by the current event.
 *
 * Along the way, a total count of affected macroblocks is also stored. When an
 * event concludes (end of video clip, or several frames without motion), the
 * detector considers this count. If the count does not meet a pre-set
 * threshold, it is discarded.
 *
 * == Output ==
 *
 * Motion events are stored in little table as rows of "coarse motion blocks".
 * A coarse motion block is a grouping of 24 H264 macroblocks (6x4).
 * The coarse motion block is represented as a uint32_t. The most significant
 * byte represents the address of the coarse block within the frame, and the
 * remaining 24 bits indicate whether or not motion was present in that
 * macroblock. The diagram below illustrates the mapping of macroblocks to bits
 * within the fine motion block.
 *
 * The full frame consists of 90 coarse motion blocks in a 10 x 9 grid.
 *
 *        Coarse motion block
 *          <-- 6 cols -->
 *  -----------------------------   ^
 * |  0 |  4 |  8 | 12 | 16 | 20 |  |
 * |  1 |  5 |  9 | 13 | 17 | 21 |  4 rows
 * |  2 |  6 | 10 | 14 | 18 | 22 |  |
 * |  3 |  7 | 11 | 15 | 19 | 23 |  v
 *  -----------------------------
 *
 * |                             |
 * |      +----------------------+
 * |      |
 * |      |
 * v      v
 *              Full frame
 *           <-- 10 cols -->
 *  --------------------------------   ^
 * |      |        |       |        |  |
 * |------+--------+-------+--------|  |
 * |      |        |       |        |
 * |------+--------+-------+--------|  9 rows
 * |      |        |       |        |
 * |------+--------+-------+--------|  |
 * |      |        |       |        |  |
 *  --------------------------------   v
 *
 */

/* This is necessary to build against ffmpeg through openwrt */
#ifdef CROSS_COMPILE
#ifndef INT64_C
#define INT64_C(c) (c ## LL)
#define UINT64_C(c) (c ## ULL)
#endif
#endif

extern "C" {
#include <unistd.h>
#include <libavutil/pixelutils.h>
#include <libavformat/avformat.h>
#ifndef CROSS_COMPILE
#include <libavutil/motion_vector.h>
#include <libswscale/swscale.h>
#endif
}


#ifndef CROSS_COMPILE
#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <iostream>
#endif

#define MB_COLS           60
#define MB_ROWS           34
#define FINE_MB_COLS       6
#define FINE_MB_ROWS       4
#define COARSE_MB_COLS    10
#define COARSE_MB_ROWS     9

#define IMAGE_COLS 960
#define IMAGE_ROWS 540

#define MOTION_FRAME_THRESHOLD 32
#define MOTION_COUNT_THRESHOLD 40
#define Y_PLANE_THRESHOLD 3000
#define UV_PLANE_THRESHOLD (Y_PLANE_THRESHOLD / 4)

#ifndef CROSS_COMPILE
using namespace cv;
using namespace std;
#endif

static AVFrame *frame = NULL;
static AVFrame *last_frame = NULL;
static AVPacket pkt;
static AVStream *video_stream = NULL;
static AVCodecContext *video_dec_ctx = NULL;
static AVFormatContext *fmt_ctx = NULL;

#ifndef CROSS_COMPILE
static AVFrame *display_frame = NULL;
struct SwsContext * img_convert_ctx;
#endif

static const char *src_filename = NULL;
static const char *output_dir = NULL;

static int motion_count = 0;
static int video_stream_idx = -1;
static uint32_t frame_duration_ms = 0;
static uint64_t file_start_time_ms = 0;

static uint8_t mbs_aggregate[MB_COLS][MB_ROWS] = {0};
static uint8_t mbs_current[MB_COLS][MB_ROWS] = {0};

#ifndef CROSS_COMPILE
static Mat grid(IMAGE_ROWS, IMAGE_COLS, CV_8UC3);
static Mat debug_blocks(IMAGE_ROWS, IMAGE_COLS, CV_8UC3);
static Mat current_motion(IMAGE_ROWS, IMAGE_COLS, CV_8UC3);
static Mat aggregate_motion(IMAGE_ROWS, IMAGE_COLS, CV_8UC3);
#endif

typedef enum {
    Y_PLANE,
    U_PLANE,
    V_PLANE,
    NUM_PLANES
} plane_index;

static void print_averror(int err)
{
    char errbuf[128];
    av_strerror(err, errbuf, sizeof(errbuf));
    fprintf(stderr, "* AVERROR: %s\n", errbuf);
}

void log_event(const char * event)
{
    int len = strlen(src_filename) + 1;
    char * escaped_filename = (char *) malloc(len);

    // replace single qutoes with double quotes
    for (int i = 0; i < len; i++) {
        if (src_filename[i] == '\'') escaped_filename[i] = '"';
        else escaped_filename[i] = src_filename[i];
    }

    fprintf(stderr, "Error in [%s]: %s\n", escaped_filename, event);

#ifdef CROSS_COMPILE
    FILE *file;
    if ((file = fopen("/click/event_log/add_event", "w"))) {
        fprintf(file, "motion_error \"file='%s' reason='%s'\" \"\"",
                escaped_filename, event);
        fclose(file);
    } else {
        fprintf(stderr, "Error: couldn't write to event log\n");
    }
#endif

    free(escaped_filename);
}

#ifndef CROSS_COMPILE
static void draw_macroblock_grid()
{
    for (int x = 0; x < IMAGE_COLS; x += 16) {
        int width = 1;
        if (((x / 16) % FINE_MB_COLS) == 0) width = 2;
        rectangle(grid, Point(x, 0), Point(x, IMAGE_ROWS), Scalar(255,255,255), 1);
    }
    for (int y = 0; y < IMAGE_ROWS; y += 16) {
        int width = 1;
        if (((y / 16) % FINE_MB_ROWS) == 0) width = 2;
        rectangle(grid, Point(0, y), Point(IMAGE_COLS, y), Scalar(255,255,255), 1);
    }
}
#endif

#ifndef CROSS_COMPILE
static void setup_display_frame()
{
    int numBytes;
    uint8_t *buffer;
    AVPixelFormat  format = AV_PIX_FMT_BGR24;

    display_frame = av_frame_alloc();
    numBytes = avpicture_get_size(format, IMAGE_COLS, IMAGE_ROWS);
    buffer = (uint8_t *) av_malloc(numBytes * sizeof(uint8_t));
    avpicture_fill((AVPicture *) display_frame, buffer, format, IMAGE_COLS, IMAGE_ROWS);
    display_frame->width = IMAGE_COLS;
    display_frame->height = IMAGE_ROWS;


    img_convert_ctx = sws_getCachedContext(NULL,
                                           video_dec_ctx->width, video_dec_ctx->height, video_dec_ctx->pix_fmt,
                                           IMAGE_COLS, IMAGE_ROWS, format, SWS_BICUBIC, NULL, NULL,NULL);

    namedWindow("debug_blocks", WINDOW_AUTOSIZE);
    namedWindow("current_motion", WINDOW_AUTOSIZE);
    moveWindow("current_motion", 0, IMAGE_ROWS);
}
#endif

static int open_codec_context(int *stream_idx, AVFormatContext *fmt_ctx, enum AVMediaType type)
{
    int ret;
    AVStream *st;
    AVCodecContext *dec_ctx = NULL;
    AVCodec *dec = NULL;
    AVDictionary *opts = NULL;

    ret = av_find_best_stream(fmt_ctx, type, -1, -1, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "Could not find %s stream in input file '%s'\n",
                av_get_media_type_string(type), src_filename);
        return ret;
    } else {
        *stream_idx = ret;
        st = fmt_ctx->streams[*stream_idx];

        frame_duration_ms = (uint32_t) ((0.001 * fmt_ctx->duration) / st->nb_frames);

        dec_ctx = st->codec;
        dec = avcodec_find_decoder(dec_ctx->codec_id);
        if (!dec) {
            fprintf(stderr, "Failed to find %s codec\n",
                    av_get_media_type_string(type));
            return AVERROR(EINVAL);
        }

        // Tell decoder to extract motion vectors
        av_dict_set(&opts, "flags2", "+export_mvs", 0);
        if ((ret = avcodec_open2(dec_ctx, dec, &opts)) < 0) {
            fprintf(stderr, "Failed to open %s codec\n",
                    av_get_media_type_string(type));
            return ret;
        }
    }

    return EXIT_SUCCESS;
}

#ifndef CROSS_COMPILE
static void draw_mb_grid(Mat& grid)
{
    for (int x = 0; x < IMAGE_COLS; x += 16) {
        int width = 1;
        if (((x / 16) % FINE_MB_COLS) == 0) width = 2;
        rectangle(grid, Point(x, 0), Point(x, IMAGE_ROWS), Scalar(255,255,255), width);
    }
    for (int y = 0; y < IMAGE_ROWS; y += 16) {
        int width = 1;
        if (((y / 16) % FINE_MB_ROWS) == 0) width = 2;
        rectangle(grid, Point(0, y), Point(IMAGE_COLS, y), Scalar(255,255,255), width);
    }
}
#endif

static void dump_motion_blocks(int start_frame, int end_frame)
{
    uint64_t event_ts_ms = (start_frame * frame_duration_ms) + file_start_time_ms;
    uint64_t event_length_ms = (end_frame - start_frame) * frame_duration_ms;

    FILE *fp;
#ifdef CROSS_COMPILE
    char name_buf[256];
    sprintf(name_buf, "%s/%.3f.motion", output_dir, event_ts_ms / 1000.0);
    fp = fopen(name_buf, "w+");
#else
    fp = stdout;
#endif

    fprintf(fp, "duration_ms: %llu\n", event_length_ms);

    int coarse_blocks = 0, fine_blocks = 0;
    for (int coarse_col = 0; coarse_col < COARSE_MB_COLS; coarse_col++) {
        for (int coarse_row = 0; coarse_row < COARSE_MB_ROWS; coarse_row++) {

            uint32_t result = (coarse_row << 28) | (coarse_col << 24);

            for (int fine_col = 0; fine_col < FINE_MB_COLS; fine_col++) {
                for (int fine_row = 0; fine_row < FINE_MB_ROWS; fine_row++) {

                    int mb_col = (coarse_col * FINE_MB_COLS) + fine_col;
                    int mb_row = (coarse_row * FINE_MB_ROWS) + fine_row;

                    if (mb_col < MB_COLS && mb_row < MB_ROWS && mbs_aggregate[mb_col][mb_row]) {
                        result |= 1 << ((FINE_MB_ROWS * fine_col) + fine_row);
                        fine_blocks++;
                    }
                }
            }

            if ((result & 0x00FFFFFF) > 0) {
               fprintf(fp, "0x%08X\n", result);
               coarse_blocks++;
            }
        }
    }

#ifdef CROSS_COMPILE
    fclose(fp);
#endif
    printf("  - Event ts = [%.3f] len = [%.3f], coarse [%d] fine [%4.1f%%]\n",
           event_ts_ms / 1000.0, event_length_ms / 1000.0, coarse_blocks,
           fine_blocks / (.01 * MB_ROWS * MB_COLS));
}

static int open_file_or_stream()
{
    int averror;

    av_register_all();
    avformat_network_init();
    AVDictionary *opts = NULL;
    av_dict_set(&opts, "rtsp_transport", "tcp", 0);
    if ((averror = avformat_open_input(&fmt_ctx, src_filename, NULL, &opts)) < 0) {
        print_averror(averror);
        log_event("Could not open source file");
        return EXIT_FAILURE;
    }

    if ((averror = avformat_find_stream_info(fmt_ctx, NULL)) < 0) {
        print_averror(averror);
        log_event("Could not find stream information");
        return EXIT_FAILURE;
    }

    if (open_codec_context(&video_stream_idx, fmt_ctx, AVMEDIA_TYPE_VIDEO) >= 0) {
        video_stream = fmt_ctx->streams[video_stream_idx];
        video_dec_ctx = video_stream->codec;
    }

    av_dump_format(fmt_ctx, 0, src_filename, 0);

    if (!video_stream) {
        log_event("Could not find video stream in input");
        return EXIT_FAILURE;
    }

    frame = av_frame_alloc();
    last_frame = av_frame_alloc();
    if (!frame || !last_frame) {
        log_event("Could not allocate frame");
        return EXIT_FAILURE;
    }

    av_init_packet(&pkt);
    pkt.data = NULL;
    pkt.size = 0;

    return EXIT_SUCCESS;
}

static int process_frames()
{
    int ret, got_frame, frame_count = 0;
    int last_motion_frame = -1, first_motion_frame = -1;
    uint64_t event_ts_ms;

#ifndef CROSS_COMPILE
    Mat img(display_frame->height,display_frame->width,CV_8UC3, display_frame->data[0]);
#endif

    av_pixelutils_sad_fn sad_y  = av_pixelutils_get_sad_fn(4, 4, 0, NULL);
    av_pixelutils_sad_fn sad_uv = av_pixelutils_get_sad_fn(3, 3, 0, NULL);
    if (!sad_y || !sad_uv) {
        log_event("Could not find SAD function");
        return EXIT_FAILURE;
    }

    while (av_read_frame(fmt_ctx, &pkt) >= 0) {
        AVPacket orig_pkt = pkt;
        do {
            int decoded = pkt.size;
            got_frame = 0;
            if (pkt.stream_index == video_stream_idx) {
                ret = avcodec_decode_video2(video_dec_ctx, frame, &got_frame, &pkt);
                if (ret < 0) {
                    log_event("Error in avcodec_decode_video2");
                    return EXIT_FAILURE;
                }

                if (got_frame) {
#ifndef CROSS_COMPILE
                    debug_blocks = Scalar(0,0,0);
                    current_motion = Scalar(0,0,0);
                    aggregate_motion = Scalar(0,0,0);
                    sws_scale(img_convert_ctx, frame->data, frame->linesize, 0,
                              video_dec_ctx->height, display_frame->data, display_frame->linesize);
#endif

                    frame_count++;
                    if (frame_count > 2) {
                        memset(mbs_current, 0, sizeof(mbs_current));

                        for (int x = 0; x < frame->width; x += 16) {
                            for (int y = 0; y < frame->height; y += 16) {
                                int sad_count[3] = {0,0,0};

                                for (int plane = 0; frame->data[plane] && frame->linesize[plane]; plane++) {
                                    int pl_x, pl_y;
                                    av_pixelutils_sad_fn sad;

                                    /* The video comes out of the camera in
                                     * I420 format, which is YUV semi-planar.
                                     * This means that for a 2 x 2 square of
                                     * pixels, there are 4 Y samples but only
                                     * 1 U sample and 1 V sample.
                                     *
                                     * Because of this, we need to adjust our
                                     * coordinates when dealing with the U and
                                     * V planes, and to scale our motion output
                                     * to match the Y plane.
                                     */
                                    if (plane == U_PLANE || plane == V_PLANE) {
                                        pl_x = x / 2;
                                        pl_y = y / 2;
                                        sad = sad_uv;
                                    } else {
                                        pl_x = x;
                                        pl_y = y;
                                        sad = sad_y;
                                    }

                                    sad_count[plane] += sad(frame->data[plane] + (pl_y * frame->linesize[plane]) + pl_x,
                                                            frame->linesize[plane],
                                                            last_frame->data[plane] + (pl_y * last_frame->linesize[plane]) + pl_x,
                                                            last_frame->linesize[plane]);
                                }

                                int combined_sad = (sad_count[Y_PLANE] + (4 * (sad_count[U_PLANE] + sad_count[V_PLANE]))) / 3;

#ifndef CROSS_COMPILE
                                /* Draw SAD data for the Y, U, V, and combined
                                 * thresholds to the OpenCV visualizer
                                 */
                                if (sad_count[Y_PLANE] > Y_PLANE_THRESHOLD)
                                    rectangle(debug_blocks, Point(x + 1, y + 1), Point(x + 5, y + 5), Scalar(160, 123, 36), CV_FILLED);

                                if (sad_count[U_PLANE] > UV_PLANE_THRESHOLD)
                                    rectangle(debug_blocks, Point(x + 6, y + 1), Point(x + 10, y + 5), Scalar(76, 231, 253), CV_FILLED);

                                if (sad_count[V_PLANE] > UV_PLANE_THRESHOLD)
                                    rectangle(debug_blocks, Point(x + 11, y + 1), Point(x + 15, y + 5), Scalar(89, 17, 216), CV_FILLED);

                                if (combined_sad > Y_PLANE_THRESHOLD)
                                    rectangle(debug_blocks, Point(x + 1, y + 6), Point(x + 15, y + 10), Scalar(33, 121, 250), CV_FILLED);
#endif

                                if (combined_sad > Y_PLANE_THRESHOLD) {
                                    mbs_current[x / 16][y / 16] = 1;
#ifndef CROSS_COMPILE
                                    int mb_x = (x / 32) * 32;
                                    int mb_y = (y / 32) * 32;
                                    rectangle(current_motion, Point(x + 5, y + 5), Point(x + 11, y + 11), Scalar(232, 168, 225), CV_FILLED);
                                    rectangle(current_motion, Point(mb_x, mb_y), Point(mb_x + 32, mb_y + 32), Scalar(255, 255, 255), 1);
#endif
                                }
                            }
                        }
                    }


#ifndef CROSS_COMPILE
                    /* Draw motion vectors. Not actually used in detection. */
                    AVFrameSideData *sd = av_frame_get_side_data(frame, AV_FRAME_DATA_MOTION_VECTORS);
                    if (sd) {
                        const AVMotionVector *mvs = (const AVMotionVector *)sd->data;
                        for (int i = 0; i < sd->size / sizeof(*mvs); i++) {
                            const AVMotionVector *mv = &mvs[i];

                            float dist = sqrt(pow(mv->src_x - mv->dst_x, 2) + pow(mv->src_y - mv->dst_y, 2));
                            if (dist > 6) {
                                rectangle(debug_blocks, Point(mv->dst_x - 7, mv->dst_y + 3), Point(mv->dst_x + 7, mv->dst_y + 7), Scalar(52,89,229), -1);
                            }
                        }
                    }
#endif

                    /* Filter macroblocks. Iterate through every macroblock in
                     * the current frame: if it has motion, and has at least one
                     * contiguous neighbor with motion, consider it significant
                     * and move it to the aggregate motion array.
                     */
                    for (int x = 0; x < MB_COLS; x++) {
                        for (int y = 0; y < MB_ROWS; y++) {
                            if (mbs_current[x][y]) {
                                if ((x > 0 && mbs_current[x - 1][y]) ||
                                    (x < MB_COLS - 1 && mbs_current[x + 1][y]) ||
                                    (y > 0 && mbs_current[x][y - 1]) ||
                                    (y < MB_ROWS - 1 && mbs_current[x][y+1])) {
                                    mbs_aggregate[x][y] = 1;
                                    last_motion_frame = frame_count;
                                    if (motion_count == 0) {
                                        first_motion_frame = frame_count;
                                    }
                                    motion_count++;
                                } else {
#ifndef CROSS_COMPILE
                                    /* Draw 'rejected' blocks in red */
                                    rectangle(aggregate_motion, Point(x * 16, y * 16), Point((x + 1) * 16, (y + 1) * 16), Scalar(40, 20, 240), CV_FILLED);
#endif
                                }
                            }
#ifndef CROSS_COMPILE
                            /* Draw the current filtered motion event */
                            if (mbs_aggregate[x][y]) {
                                rectangle(aggregate_motion, Point(x * 16 + 1, y * 16 + 1), Point((x + 1) * 16 - 1, (y + 1) * 16 - 1), Scalar(255, 132, 71), CV_FILLED);
                            }
#endif
                        }
                    }

                    /* Store the last frame for SAD comparison */
                    av_frame_unref(last_frame);
                    av_frame_move_ref(last_frame, frame);
#ifdef DEBUG
                    printf("COUNT %d  LAST %d  DIFF %d   MOT %d\n", frame_count, last_motion_frame, frame_count - last_motion_frame, motion_count);
#endif

#ifndef CROSS_COMPILE
                    if (motion_count > 0) {
                        putText(current_motion, "EVENT", Point(20,100), FONT_HERSHEY_SIMPLEX, 2, Scalar(255,255,255), 3, 8);
                    }
                    int pause = 0;
#endif

                    if (last_motion_frame > -1 && frame_count - last_motion_frame > MOTION_FRAME_THRESHOLD) {
#ifndef CROSS_COMPILE
                      pause = 1;
                      if (motion_count > MOTION_COUNT_THRESHOLD) {
                        putText(current_motion, "** SAVE **", Point(20,200), FONT_HERSHEY_SIMPLEX, 2, Scalar(255,255,255), 3, 8);
                      } else {
                        putText(current_motion, "** DISCARD **", Point(20,200), FONT_HERSHEY_SIMPLEX, 2, Scalar(255,255,255), 3, 8);
                      }
#endif

                      if (motion_count > MOTION_COUNT_THRESHOLD) {
                        dump_motion_blocks(first_motion_frame, last_motion_frame);
                        last_motion_frame = -1;
                        motion_count = 0;
                        memset(mbs_aggregate, 0, sizeof(mbs_aggregate));
                      }

                    }

#ifndef CROSS_COMPILE
                    cv::addWeighted(grid, 0.1, debug_blocks, 1.0, 0.0, debug_blocks);
                    cv::addWeighted(grid, 0.1, current_motion, 1.0, 0.0, current_motion);
                    cv::addWeighted(current_motion, 1.0, aggregate_motion, 1.0, 0.0, current_motion);
                    cv::addWeighted(debug_blocks, 0.65, img, 0.65, 0.0, debug_blocks);
                    cv::addWeighted(current_motion, 0.65, img, 0.65, 0.0, current_motion);
                    cv::imshow("debug_blocks", debug_blocks);
                    cv::imshow("current_motion", current_motion);

                    int key = cvWaitKey(1);
                    if (key == ' ') cvWaitKey(-1);
                    //if (pause) cvWaitKey(1500);
                    pause = 0;
#endif

                }
            }
            ret = decoded;

            if (ret < 0)
                break;
            pkt.data += ret;
            pkt.size -= ret;
        } while (pkt.size > 0);
        av_packet_unref(&orig_pkt);
    }

    if (motion_count > MOTION_COUNT_THRESHOLD) {
      dump_motion_blocks(first_motion_frame, last_motion_frame);
#ifndef CROSS_COMPILE
      putText(current_motion, "EVENT", Point(20,100), FONT_HERSHEY_SIMPLEX, 2, Scalar(255,255,255), 3, 8);
      putText(current_motion, "** SAVE **", Point(20,200), FONT_HERSHEY_SIMPLEX, 2, Scalar(255,255,255), 3, 8);
    } else if (motion_count > 0) {
      putText(current_motion, "EVENT", Point(20,100), FONT_HERSHEY_SIMPLEX, 2, Scalar(255,255,255), 3, 8);
      putText(current_motion, "** DISCARD **", Point(20,200), FONT_HERSHEY_SIMPLEX, 2, Scalar(255,255,255), 3, 8);
#endif
    }

#ifndef CROSS_COMPILE
    putText(current_motion, "THE END", Point(20,300), FONT_HERSHEY_SIMPLEX, 2, Scalar(255,255,255), 3, 8);
    cv::imshow("current_motion", current_motion);
    cvWaitKey(-1);
#endif

    avcodec_close(video_dec_ctx);
    avformat_close_input(&fmt_ctx);
    av_frame_free(&frame);

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    int ret;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <video>\n", argv[0]);
        fprintf(stderr, "  <video> can be a file or an RTSP stream.\n");
        fprintf(stderr, "  <output_dir> output directory.\n");
        return EXIT_FAILURE;
    }
    src_filename = argv[1];
    output_dir = argv[2];

    printf("Detector : processing [%s]\n", argv[1]);

#ifdef CROSS_COMPILE
    uint64_t file_ctime_s, file_ctime_ms;
    char buf[256] = {0};
    strncpy(buf, src_filename, sizeof(buf) - 1);
    if (sscanf(basename(buf), "%llu.%llu.mp4", &file_ctime_s, &file_ctime_ms) != 2) {
        ret = EXIT_FAILURE;
        log_event("Timestamp could not be parsed from filename");
        goto cleanup;
    }

    file_start_time_ms = file_ctime_ms + (file_ctime_s * 1000);
#endif

    ret = open_file_or_stream();
    if (ret == EXIT_FAILURE) goto cleanup;

#ifndef CROSS_COMPILE
    setup_display_frame();
    draw_macroblock_grid();
#endif

    ret = process_frames();
    if (ret == EXIT_FAILURE) goto cleanup;

    printf("Success!\n");

cleanup:

    return ret;
}
