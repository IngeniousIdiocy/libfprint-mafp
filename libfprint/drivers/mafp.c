// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Microarray MAFP8800 SPI Fingerprint Sensor Driver (FP36 variant)
 *
 * Copyright (C) 2026 Mark (GPD MicroPC 2 reverse-engineering project)
 *
 * Protocol decoded from the community libfprint driver binary and
 * verified against working hardware. Uses FP36 register-level SPI
 * protocol (match-on-host mode).
 *
 * Architecture: FpDevice subclass with a dedicated worker thread.
 * All SPI operations run in the worker thread. The main GLib thread
 * dispatches enroll/verify/identify requests via GCond signaling.
 */

#define FP_COMPONENT "mafp"

#include "drivers_api.h"

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>


/* ─── constants (from community driver binary decode) ────────────── */

/* Image geometry: 160 rows × 37 pixels, 74 bytes/row (2 hdr + 72 pixel) */
#define MAFP_ROWS             160
#define MAFP_COLS             37
#define MAFP_ROW_BYTES        74       /* 0x4A */
#define MAFP_PIXELS           (MAFP_ROWS * MAFP_COLS)  /* 5920 */
#define MAFP_FRAME_BYTES      (320 * MAFP_ROW_BYTES)   /* 0x5C80 = 23680 */
#define MAFP_ENHANCED_COLS    36       /* column 0 stripped */
#define MAFP_ENHANCED_PIXELS  (MAFP_ROWS * MAFP_ENHANCED_COLS)  /* 5760 */

/* SPI */
#define MAFP_SPI_SPEED        4000000
#define MAFP_RAW_READ_SZ      20480    /* 0x5000 */

/* Chip ID */
#define MAFP_CHIPID_FP36      0x24

/* Detection thresholds (from community binary) */
#define MAFP_DETECT_PX_THRESH 320      /* 0x140: per-pixel delta for "changed" */
#define MAFP_DETECT_RAW_LIMIT 178559   /* 0x2B97F: count*100 must exceed this */
#define MAFP_STABLE_SAD_LIMIT 114687   /* 0x1C1FF: sum-of-abs-diffs for "stable" */

/* Enrollment */
#define MAFP_ENROLL_STAGES    8

/* Matching: NCC threshold (0..1000) */
/* Approximate pixels-per-mm (sensor ~4.6mm wide, 36 px) */
#define MAFP_PPMM             8.0

/* NCC matching threshold and vertical shift range */
#define MAFP_MATCH_THRESH     500
#define MAFP_SHIFT_MAX        20

/* Template: 8-bit enhanced pixels, MAFP_ENHANCED_PIXELS per sample */
#define MAFP_TPL_SAMPLE_SZ    MAFP_ENHANCED_PIXELS
#define MAFP_TPL_HDR_SZ       4
#define MAFP_TPL_BUF_SZ       (MAFP_TPL_HDR_SZ + MAFP_ENROLL_STAGES * MAFP_TPL_SAMPLE_SZ)

/* Calibration file */
#define MAFP_CALIB_PATH       "/var/lib/fprint/mafp_calibration"
#define MAFP_CALIB_SZ         0x2E50   /* 11856 bytes */
#define MAFP_CALIB_MAGIC      0x24

/* ─── device struct ──────────────────────────────────────────────── */

struct _FpiDeviceMafp
{
  FpDevice parent;

  int spi_fd;

  /* calibration data (loaded from file or computed) */
  guint8  calib[MAFP_CALIB_SZ];

  /* image buffers (each MAFP_FRAME_BYTES = 23680 bytes of u16 in LE) */
  guint8 *bg_frame;          /* background/image_data reference */
  guint8 *cur_frame;         /* current capture */
  guint8 *stab_frame;        /* stability reference */
  guint8 *detect_ref;        /* best-finger reference (hysteresis) */

  /* enhanced output (MAFP_ENHANCED_PIXELS × 2 bytes, u16 LE) */
  guint16 *enhanced;

  /* SPI scratch buffer */
  guint8 *spi_buf;

  /* detection hysteresis state */
  gboolean detect_flag;      /* was finger detected last call */
  gint32   gray_value;       /* saved detection score */

  /* worker thread */
  GThread    *worker;
  GMutex      lock;
  GCond       cond;
  gboolean    exit_flag;
  gboolean    has_work;
  gboolean    canceled;
  void      (*run_func)(struct _FpiDeviceMafp *self);
};

G_DECLARE_FINAL_TYPE (FpiDeviceMafp, fpi_device_mafp, FPI, DEVICE_MAFP, FpDevice)
G_DEFINE_TYPE (FpiDeviceMafp, fpi_device_mafp, FP_TYPE_DEVICE)

/* ─── SPI transport ──────────────────────────────────────────────── */

/*
 * Register read/write: 4-byte full-duplex SPI.
 * TX: [reg, val, 0x00, 0x00]
 * Response byte: rx[2] (verified against community driver)
 */
static gint
mafp_set_reg (FpiDeviceMafp *self, guint8 reg, guint8 val)
{
  guint8 tx[4] = { reg, val, 0x00, 0x00 };
  guint8 rx[4] = { 0 };
  struct spi_ioc_transfer tr = {
    .tx_buf = (unsigned long) tx, .rx_buf = (unsigned long) rx,
    .len = 4, .speed_hz = MAFP_SPI_SPEED, .bits_per_word = 8,
  };

  if (ioctl (self->spi_fd, SPI_IOC_MESSAGE (1), &tr) < 0)
    return -1;
  return rx[2];
}

static gboolean
mafp_spi_xfer (FpiDeviceMafp *self, guint8 *buf, gsize len)
{
  struct spi_ioc_transfer tr = {
    .tx_buf = (unsigned long) buf, .rx_buf = (unsigned long) buf,
    .len = (guint32) len, .speed_hz = MAFP_SPI_SPEED, .bits_per_word = 8,
  };
  return ioctl (self->spi_fd, SPI_IOC_MESSAGE (1), &tr) >= 0;
}

/* SPI read: send first 2 bytes of buf, receive len bytes back.
 * Matches community mafp_sensor_spi_read_data semantics. */
static gboolean
mafp_spi_read_data (FpiDeviceMafp *self, guint8 *buf, gsize len)
{
  /* The community driver does write(fd, buf, 2) then read(fd, spi_buf, len).
   * With direct ioctl, we do a single full-duplex transfer of the full length. */
  return mafp_spi_xfer (self, buf, len);
}

/* ─── FP36 chip protocol ─────────────────────────────────────────── */

static gboolean
mafp_fp36_reset (FpiDeviceMafp *self)
{
  mafp_set_reg (self, 0x8C, 0xFF);
  for (int i = 0; i < 20; i++)
    {
      g_usleep (1000);
      if (mafp_set_reg (self, 0x04, 0x00) == MAFP_CHIPID_FP36)
        return TRUE;
    }
  fp_warn ("FP36 reset timeout");
  return FALSE;
}

static void
mafp_fp36_capture_mode (FpiDeviceMafp *self, guint8 gain, guint8 integration, guint8 dac)
{
  mafp_set_reg (self, 0x20, 0x8F);
  mafp_set_reg (self, 0x18, gain);
  mafp_set_reg (self, 0x38, 0x02);
  mafp_set_reg (self, 0x40, 0x00);
  mafp_set_reg (self, 0x48, 0x25);
  mafp_set_reg (self, 0x3C, integration);
  mafp_set_reg (self, 0x44, dac);

  /* Flush/sync: read 0x26 bytes with cmd 0x78 */
  guint8 flush[0x26];
  memset (flush, 0x00, sizeof (flush));
  flush[0] = 0x78;
  mafp_spi_read_data (self, flush, 0x26);
}

static int
mafp_fp36_read_image (FpiDeviceMafp *self, guint8 *out_frame)
{
  guint8 *buf = self->spi_buf;
  memset (buf, 0xFF, MAFP_RAW_READ_SZ);
  buf[0] = 0x70;

  if (!mafp_spi_read_data (self, buf, MAFP_RAW_READ_SZ))
    return 0;

  /* Scan for row markers and pack rows into out_frame */
  int rows = 0;
  int i = 0;

  while (i < MAFP_RAW_READ_SZ - 4 && rows < MAFP_ROWS)
    {
      if (buf[i] == 0x00 && buf[i + 1] == 0x00 &&
          buf[i + 2] == 0x0A && (buf[i + 3] & 0xF0) == 0x50)
        {
          int src = i + 4;
          if (src + MAFP_ROW_BYTES > MAFP_RAW_READ_SZ)
            break;
          memcpy (out_frame + rows * MAFP_ROW_BYTES, buf + src, MAFP_ROW_BYTES);
          rows++;
          i = src + MAFP_ROW_BYTES;
        }
      else
        {
          i++;
        }
    }

  /* Byte-swap: big-endian to little-endian u16 in-place */
  for (int j = 0; j < rows * MAFP_ROW_BYTES; j += 2)
    {
      guint8 tmp = out_frame[j];
      out_frame[j] = out_frame[j + 1];
      out_frame[j + 1] = tmp;
    }

  return rows;
}

/* Capture one frame: reset → capture_mode → read_image */
static int
mafp_fp36_capture (FpiDeviceMafp *self, guint8 *frame)
{
  mafp_fp36_reset (self);
  mafp_fp36_capture_mode (self, self->calib[1], 0x02, 0xA1);
  return mafp_fp36_read_image (self, frame);
}

/* Read a u16 pixel from a frame buffer (row-major, LE) */
static inline guint16
frame_pixel (const guint8 *frame, int row, int col)
{
  int off = row * MAFP_ROW_BYTES + col * 2;
  return (guint16) frame[off] | ((guint16) frame[off + 1] << 8);
}

/* ─── detection mode setup ───────────────────────────────────────── */

static void
mafp_fp36_int_ctl_init (FpiDeviceMafp *self)
{
  mafp_set_reg (self, 0x10, 0xBF);
  guint8 flush[0x26];
  memset (flush, 0x00, sizeof (flush));
  flush[0] = 0x78;
  mafp_spi_read_data (self, flush, 0x26);

  mafp_set_reg (self, 0x20, 0x80);
  mafp_set_reg (self, 0x28, 0x00);
  mafp_set_reg (self, 0x38, 0x02);
  mafp_set_reg (self, 0x3C, 0x38);
  mafp_set_reg (self, 0x44, 0x78);
  mafp_set_reg (self, 0x40, 0x08);
  mafp_set_reg (self, 0x48, 0x1E);
  mafp_set_reg (self, 0x4C, 0x88);
  mafp_set_reg (self, 0x50, 0x00);
  mafp_set_reg (self, 0x54, 0x00);
  mafp_set_reg (self, 0x58, 0x00);
  mafp_set_reg (self, 0x5C, 0x00);
}

static void
mafp_fp36_calc_grey (FpiDeviceMafp *self, guint8 int_val,
                     guint8 *g0, guint8 *g1, guint8 *g2)
{
  mafp_set_reg (self, 0x18, int_val);
  mafp_set_reg (self, 0x84, 0x00);
  g_usleep (10000);
  mafp_set_reg (self, 0x88, 0x00);

  for (int i = 0; i < 20; i++)
    {
      g_usleep (1000);
      if (mafp_set_reg (self, 0x04, 0x00) == MAFP_CHIPID_FP36)
        break;
    }

  *g0 = (guint8) mafp_set_reg (self, 0x54, 0x00);
  *g1 = (guint8) mafp_set_reg (self, 0x58, 0x00);
  *g2 = (guint8) mafp_set_reg (self, 0x5C, 0x00);
}

static void
mafp_fp36_detect_mode (FpiDeviceMafp *self)
{
  mafp_fp36_reset (self);
  mafp_set_reg (self, 0x10, 0xBF);

  guint8 flush[0x26];
  memset (flush, 0x00, sizeof (flush));
  flush[0] = 0x78;
  mafp_spi_read_data (self, flush, 0x26);

  mafp_set_reg (self, 0x20, 0x80);
  mafp_set_reg (self, 0x28, 0x00);
  mafp_set_reg (self, 0x38, 0x06);   /* detect scan mode, NOT 0x02 */
  mafp_set_reg (self, 0x3C, 0x38);
  mafp_set_reg (self, 0x44, 0x78);
  mafp_set_reg (self, 0x40, 0x08);
  mafp_set_reg (self, 0x48, 0x1E);
  mafp_set_reg (self, 0x4C, 0x88);
  mafp_set_reg (self, 0x50, 0xFF);
  mafp_set_reg (self, 0x54, self->calib[4]);
  mafp_set_reg (self, 0x58, self->calib[5]);
  mafp_set_reg (self, 0x5C, self->calib[6]);
  mafp_set_reg (self, 0x18, self->calib[2]);
  mafp_set_reg (self, 0x84, 0x00);
}

/* ─── calibration ────────────────────────────────────────────────── */

static guint8
mafp_crc8 (const guint8 *data, gsize len)
{
  guint8 crc = 0;
  for (gsize i = 0; i < len; i++)
    crc ^= data[i];
  return crc;
}

static gboolean
mafp_load_calib (FpiDeviceMafp *self)
{
  FILE *f = fopen (MAFP_CALIB_PATH, "rb");
  if (!f)
    return FALSE;
  gsize n = fread (self->calib, 1, MAFP_CALIB_SZ, f);
  fclose (f);
  if (n < MAFP_CALIB_SZ)
    return FALSE;
  if (self->calib[0] != MAFP_CALIB_MAGIC)
    return FALSE;
  guint8 crc = mafp_crc8 (self->calib, 0x2E4C);
  return self->calib[0x2E4C] == crc;
}

static void
mafp_save_calib (FpiDeviceMafp *self)
{
  self->calib[0] = MAFP_CALIB_MAGIC;
  guint8 crc = mafp_crc8 (self->calib, 0x2E4C);
  self->calib[0x2E4C] = crc;

  g_mkdir_with_parents ("/var/lib/fprint", 0755);
  FILE *f = fopen (MAFP_CALIB_PATH, "wb");
  if (f)
    {
      fwrite (self->calib, 1, MAFP_CALIB_SZ, f);
      fsync (fileno (f));
      fclose (f);
      fp_info ("calibration saved to %s", MAFP_CALIB_PATH);
    }
}

static void
mafp_fp36_calibrate (FpiDeviceMafp *self)
{
  /* Try loading cached calibration */
  if (mafp_load_calib (self))
    {
      fp_info ("loaded cached calibration (gain=%d, detect_int=%d, thresh=%d/%d/%d)",
               self->calib[1], self->calib[2],
               self->calib[4], self->calib[5], self->calib[6]);
      /* Restore background image from calibration data */
      memcpy (self->bg_frame, self->calib + 8,
              MIN ((gsize)(MAFP_CALIB_SZ - 8), (gsize) MAFP_FRAME_BYTES));
      return;
    }

  fp_info ("running live calibration...");

  /* Binary search for optimal capture gain.
   * Community driver reads 0x400 bytes, sums BE u16 pixel pairs.
   * Target: total pixel sum just below 0x4007F (262,271).
   * This means average pixel ~ 512 across ~512 bytes of pixel data. */
  int low = 0, high = 255, mid = 128;

  for (int iter = 0; iter < 8; iter++)
    {
      mid = (low + high) / 2;
      mafp_fp36_reset (self);
      mafp_fp36_capture_mode (self, (guint8) mid, 0x4C, 0x54);

      /* Read exactly 0x400 bytes (matches community driver) */
      guint8 raw[0x400];
      memset (raw, 0xFF, 0x400);
      raw[0] = 0x70;
      mafp_spi_read_data (self, raw, 0x400);

      /* Community driver: parses rows from 0x400 raw bytes, packs them
       * to start of buffer, then sums exactly 0x250 bytes (296 BE u16
       * values = 4 rows × 37 pixels) regardless of rows found.
       * Target 0x4007F across those 148 u16 values → avg ~1772/pixel. */
      long total = 0;
      int nrows = 0;
      int i = 0;
      /* Parse rows and pack to start of buffer (same as community) */
      while (i < 0x400 - 4 && nrows < 8)
        {
          if (raw[i] == 0x00 && raw[i+1] == 0x00 &&
              raw[i+2] == 0x0A && (raw[i+3] & 0xF0) == 0x50)
            {
              int src = i + 4;
              if (src + MAFP_ROW_BYTES > 0x400)
                break;
              memmove (raw + nrows * MAFP_ROW_BYTES, raw + src, MAFP_ROW_BYTES);
              nrows++;
              i = src + MAFP_ROW_BYTES;
            }
          else
            i++;
        }
      /* Sum exactly 0x250 bytes (148 u16 values) from packed data */
      for (int j = 0; j < 0x250; j += 2)
        total += ((guint16) raw[j] << 8) | raw[j + 1];

      fp_dbg ("calibrate gain search: gain=%d total=%ld (target=%d)", mid, total, 0x4007F);

      if (total > 0x4007F)
        high = mid;
      else
        low = mid;
    }

  self->calib[1] = (guint8) mid;
  fp_info ("calibration: gain=%d", mid);

  /* Capture background image with found gain */
  mafp_fp36_capture (self, self->bg_frame);
  memcpy (self->calib + 8, self->bg_frame,
          MIN ((gsize)(MAFP_CALIB_SZ - 8), (gsize) MAFP_FRAME_BYTES));

  /* 3-pass threshold search for detection */
  guint8 g0, g1, g2;
  guint8 final_int = 0;

  /* Coarse: step 16 */
  for (int v = 0; v < 256; v += 16)
    {
      mafp_fp36_reset (self);
      mafp_fp36_int_ctl_init (self);
      mafp_fp36_calc_grey (self, (guint8) v, &g0, &g1, &g2);
      if (g0 > 100 && g1 > 100 && g2 > 100)
        { final_int = (guint8)(v > 15 ? v - 15 : 0); break; }
    }

  /* Fine: step 4 */
  for (int v = final_int; v < final_int + 16; v += 4)
    {
      mafp_fp36_reset (self);
      mafp_fp36_int_ctl_init (self);
      mafp_fp36_calc_grey (self, (guint8) v, &g0, &g1, &g2);
      if (g0 > 100 && g1 > 100 && g2 > 100)
        { final_int = (guint8) v; break; }
    }

  /* Finest: step 1 */
  for (int v = (final_int > 3 ? final_int - 3 : 0); v <= final_int; v++)
    {
      mafp_fp36_reset (self);
      mafp_fp36_int_ctl_init (self);
      mafp_fp36_calc_grey (self, (guint8) v, &g0, &g1, &g2);
      if (g0 > 100 && g1 > 100 && g2 > 100)
        { final_int = (guint8) v; break; }
    }

  self->calib[2] = final_int > 0 ? final_int - 1 : 0;
  self->calib[3] = 0xFF;
  self->calib[4] = g0 > 20 ? g0 - 20 : 0;
  self->calib[5] = g1 > 20 ? g1 - 20 : 0;
  self->calib[6] = g2 > 20 ? g2 - 20 : 0;

  fp_info ("calibration: detect_int=%d thresh=%d/%d/%d",
           self->calib[2], self->calib[4], self->calib[5], self->calib[6]);

  mafp_save_calib (self);
}

/* ─── finger detection (exact community algorithm) ───────────────── */

static gboolean
mafp_fp36_finger_is_detect (FpiDeviceMafp *self)
{
  /* Capture frame */
  mafp_fp36_capture (self, self->cur_frame);

  /* Count pixels where background is darker than current by > MAFP_DETECT_PX_THRESH.
   * Community checks (bg - cur) > threshold, i.e. finger DARKENS the sensor. */
  int changed = 0;
  for (int row = 0; row < MAFP_ROWS; row++)
    for (int col = 1; col < MAFP_COLS; col++)  /* skip column 0 */
      {
        gint32 bg = (gint32) frame_pixel (self->bg_frame, row, col);
        gint32 cur = (gint32) frame_pixel (self->cur_frame, row, col);
        if ((bg - cur) > MAFP_DETECT_PX_THRESH)
          changed++;
      }

  gint32 raw_score = changed * 100;
  gboolean detected = raw_score > MAFP_DETECT_RAW_LIMIT;

  /* Compute percentage for hysteresis */
  gint32 pct = (MAFP_ENHANCED_PIXELS > 0)
    ? (changed * 100) / MAFP_ENHANCED_PIXELS : 0;

  if (!detected)
    {
      self->detect_flag = FALSE;
      return FALSE;
    }

  /* Hysteresis */
  if (!self->detect_flag)
    {
      /* First detection: clear reference, init score */
      memset (self->detect_ref, 0, MAFP_FRAME_BYTES);
      self->gray_value = 0;
    }

  if (self->gray_value < pct)
    {
      /* Finger pressing harder: update reference to track peak */
      memcpy (self->detect_ref, self->cur_frame, MAFP_FRAME_BYTES);
      self->gray_value = pct;
    }

  self->detect_flag = TRUE;
  return TRUE;
}

static gboolean
mafp_fp36_finger_is_stable (FpiDeviceMafp *self)
{
  long sad = 0;
  for (int row = 0; row < MAFP_ROWS; row++)
    for (int col = 1; col < MAFP_COLS; col++)
      {
        gint32 a = (gint32) frame_pixel (self->cur_frame, row, col);
        gint32 b = (gint32) frame_pixel (self->stab_frame, row, col);
        gint32 d = b - a;
        if (d < 0) d = -d;
        sad += d;
      }
  return sad <= MAFP_STABLE_SAD_LIMIT;
}

/* ─── image enhancement ──────────────────────────────────────────── */

/*
 * Enhancement: bg_frame + 10000 - cur_frame
 * bg_frame = no-finger background (from calibration, stable across sessions)
 * cur_frame = current finger-present capture
 * Finger darkens pixels, so bg > cur → positive result = ridge depth.
 */
static void
mafp_fp36_enhance (FpiDeviceMafp *self)
{
  guint16 *out = self->enhanced;
  const guint8 *bg = self->bg_frame;       /* no-finger background */
  const guint8 *finger = self->cur_frame;  /* current capture with finger */

  guint16 px_min = 0xFFFF, px_max = 0;

  /* Background subtract with +10000 offset, skip column 0 */
  for (int row = 0; row < MAFP_ROWS; row++)
    for (int col = 1; col < MAFP_COLS; col++)
      {
        guint16 bg_val = frame_pixel (bg, row, col);
        guint16 fg_val = frame_pixel (finger, row, col);
        guint16 val = (guint16)((bg_val + 10000 - fg_val) & 0xFFFF);
        int idx = row * MAFP_ENHANCED_COLS + (col - 1);
        out[idx] = val;
        if (val < px_min) px_min = val;
        if (val > px_max) px_max = val;
      }

  guint16 range = px_max - px_min;
  if (range <= 50)
    {
      memset (out, 0, MAFP_ENHANCED_PIXELS * sizeof (guint16));
      return;
    }

  /* Normalize to full 16-bit range */
  for (int i = 0; i < MAFP_ENHANCED_PIXELS; i++)
    {
      guint32 val = out[i] - px_min;
      val = (val * 0xFFFF) / range;
      out[i] = (guint16) MIN (val, 0xFFFF);
    }
}

/* ─── NCC matching with vertical translation search ──────────────── */

static double
ncc_region (const guint8 *a, int a_off,
            const guint8 *b, int b_off, int rows)
{
  int n = rows * MAFP_ENHANCED_COLS;
  const guint8 *ap = a + a_off * MAFP_ENHANCED_COLS;
  const guint8 *bp = b + b_off * MAFP_ENHANCED_COLS;

  gint64 sum_a = 0, sum_b = 0;
  for (int i = 0; i < n; i++)
    { sum_a += ap[i]; sum_b += bp[i]; }
  gint32 mean_a = (gint32)(sum_a / n);
  gint32 mean_b = (gint32)(sum_b / n);

  gint64 sum_ab = 0, sum_aa = 0, sum_bb = 0;
  for (int i = 0; i < n; i++)
    {
      gint32 da = (gint32) ap[i] - mean_a;
      gint32 db = (gint32) bp[i] - mean_b;
      sum_ab += da * db;
      sum_aa += da * da;
      sum_bb += db * db;
    }
  if (sum_aa == 0 || sum_bb == 0)
    return 0.0;
  return (double) sum_ab / sqrt ((double) sum_aa * (double) sum_bb);
}

static int
mafp_match_score (const guint8 *a, const guint8 *b)
{
  double best = -1.0;
  int overlap = MAFP_ROWS - MAFP_SHIFT_MAX;

  for (int shift = -MAFP_SHIFT_MAX; shift <= MAFP_SHIFT_MAX; shift++)
    {
      int a_off = (shift >= 0) ? shift : 0;
      int b_off = (shift >= 0) ? 0 : -shift;
      double s = ncc_region (a, a_off, b, b_off, overlap);
      if (s > best)
        best = s;
    }
  return (int) (best * 1000.0);
}

/* Convert enhanced 16-bit to 8-bit */
static void
mafp_enhanced_to_8bit (const guint16 *src, guint8 *dst)
{
  for (int i = 0; i < MAFP_ENHANCED_PIXELS; i++)
    dst[i] = (guint8) (src[i] >> 8);
}

/* ─── check cancellation ─────────────────────────────────────────── */

static gboolean
mafp_is_canceled (FpiDeviceMafp *self)
{
  return self->canceled || fpi_device_action_is_cancelled (FP_DEVICE (self));
}

/* ─── enroll (runs in worker thread) ─────────────────────────────── */

static void
mafp_enroll_run (FpiDeviceMafp *self)
{
  fp_info ("enroll: starting");

  /* Calibrate (loads from file or runs live) */
  mafp_fp36_calibrate (self);

  /* Enter detection mode with calibrated thresholds */
  mafp_fp36_detect_mode (self);

  /* Allocate template buffer */
  g_autofree guint8 *tpl_buf = g_malloc0 (MAFP_TPL_BUF_SZ);
  g_autofree guint8 *norm8 = g_malloc0 (MAFP_ENHANCED_PIXELS);
  int tpl_count = 0;

  for (int stage = 0; stage < MAFP_ENROLL_STAGES; stage++)
    {
      if (mafp_is_canceled (self))
        goto canceled;

      fp_info ("enroll: stage %d/%d — waiting for finger", stage + 1, MAFP_ENROLL_STAGES);

      /* Reset detection state */
      self->detect_flag = FALSE;
      self->gray_value = 0;

      /* Wait for finger */
      while (!mafp_is_canceled (self))
        {
          if (mafp_fp36_finger_is_detect (self))
            break;
          g_usleep (50000);
        }
      if (mafp_is_canceled (self))
        goto canceled;

      fp_info ("enroll: finger detected, waiting for stable");

      /* Wait for stable */
      memcpy (self->stab_frame, self->cur_frame, MAFP_FRAME_BYTES);
      gboolean stable = FALSE;
      for (int tries = 0; tries < 20; tries++)
        {
          g_usleep (50000);
          mafp_fp36_capture (self, self->cur_frame);
          if (!mafp_fp36_finger_is_detect (self))
            break;
          if (mafp_fp36_finger_is_stable (self))
            { stable = TRUE; break; }
          memcpy (self->stab_frame, self->cur_frame, MAFP_FRAME_BYTES);
        }

      if (!stable)
        {
          fp_info ("enroll: not stable, retrying stage");
          fpi_device_enroll_progress (FP_DEVICE (self), stage, NULL,
            fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
          stage--;
          continue;
        }

      fp_info ("enroll: stable, capturing template");

      /* Enhance image and store as 8-bit template */
      mafp_fp36_enhance (self);
      mafp_enhanced_to_8bit (self->enhanced, norm8);
      memcpy (tpl_buf + MAFP_TPL_HDR_SZ + tpl_count * MAFP_TPL_SAMPLE_SZ,
              norm8, MAFP_TPL_SAMPLE_SZ);
      tpl_count++;

      fpi_device_enroll_progress (FP_DEVICE (self), stage, NULL, NULL);

      fp_info ("enroll: stage %d done, waiting for finger removal", stage + 1);

      /* Wait for finger removal */
      while (!mafp_is_canceled (self))
        {
          g_usleep (100000);
          self->detect_flag = FALSE;
          self->gray_value = 0;
          if (!mafp_fp36_finger_is_detect (self))
            break;
        }
    }

  if (mafp_is_canceled (self))
    goto canceled;

  /* Store template count and serialize */
  memcpy (tpl_buf, &tpl_count, sizeof (gint32));

  FpPrint *print = NULL;
  fpi_device_get_enroll_data (FP_DEVICE (self), &print);
  GVariant *data = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                               tpl_buf, MAFP_TPL_BUF_SZ, 1);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, FALSE);
  g_object_set (print, "fpi-data", data, NULL);

  fp_info ("enroll: complete, %d templates", tpl_count);
  fpi_device_enroll_complete (FP_DEVICE (self), g_object_ref (print), NULL);
  return;

canceled:
  fp_info ("enroll: canceled");
  fpi_device_enroll_complete (FP_DEVICE (self), NULL,
    fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
}

/* ─── verify/identify (runs in worker thread) ────────────────────── */

static void
mafp_verify_run (FpiDeviceMafp *self)
{
  FpiDeviceAction action = fpi_device_get_current_action (FP_DEVICE (self));

  fp_info ("verify/identify: starting");

  mafp_fp36_calibrate (self);
  mafp_fp36_detect_mode (self);

  /* Reset detection */
  self->detect_flag = FALSE;
  self->gray_value = 0;

  /* Wait for finger */
  while (!mafp_is_canceled (self))
    {
      if (mafp_fp36_finger_is_detect (self))
        break;
      g_usleep (50000);
    }

  if (mafp_is_canceled (self))
    goto canceled;

  /* Wait for stable */
  memcpy (self->stab_frame, self->cur_frame, MAFP_FRAME_BYTES);
  for (int i = 0; i < 20; i++)
    {
      g_usleep (50000);
      mafp_fp36_capture (self, self->cur_frame);
      if (mafp_fp36_finger_is_stable (self))
        break;
      memcpy (self->stab_frame, self->cur_frame, MAFP_FRAME_BYTES);
    }

  /* Enhance and convert to 8-bit */
  mafp_fp36_enhance (self);
  g_autofree guint8 *norm8 = g_malloc0 (MAFP_ENHANCED_PIXELS);
  mafp_enhanced_to_8bit (self->enhanced, norm8);

  if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      FpPrint *enrolled = NULL;
      fpi_device_get_verify_data (FP_DEVICE (self), &enrolled);

      g_autoptr (GVariant) var = NULL;
      g_object_get (enrolled, "fpi-data", &var, NULL);

      gboolean matched = FALSE;
      if (var)
        {
          gsize tpl_sz = 0;
          const guint8 *tpl = g_variant_get_fixed_array (var, &tpl_sz, 1);
          if (tpl_sz >= MAFP_TPL_HDR_SZ)
            {
              gint32 count = 0;
              memcpy (&count, tpl, sizeof (gint32));
              for (int i = 0; i < count && i < MAFP_ENROLL_STAGES; i++)
                {
                  const guint8 *sample = tpl + MAFP_TPL_HDR_SZ + i * MAFP_TPL_SAMPLE_SZ;
                  int score = mafp_match_score (norm8, sample);
                  fp_info ("verify: template %d score=%d (thresh=%d)",
                           i, score, MAFP_MATCH_THRESH);
                  if (score >= MAFP_MATCH_THRESH)
                    { matched = TRUE; break; }
                }
            }
        }

      fpi_device_verify_report (FP_DEVICE (self),
                                 matched ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                                 NULL, NULL);
      fpi_device_verify_complete (FP_DEVICE (self), NULL);
    }
  else /* IDENTIFY */
    {
      GPtrArray *gallery = NULL;
      fpi_device_get_identify_data (FP_DEVICE (self), &gallery);

      FpPrint *matched_print = NULL;
      for (guint gi = 0; gi < gallery->len; gi++)
        {
          FpPrint *p = g_ptr_array_index (gallery, gi);
          g_autoptr (GVariant) var = NULL;
          g_object_get (p, "fpi-data", &var, NULL);
          if (!var) continue;

          gsize tpl_sz = 0;
          const guint8 *tpl = g_variant_get_fixed_array (var, &tpl_sz, 1);
          if (tpl_sz < MAFP_TPL_HDR_SZ) continue;

          gint32 count = 0;
          memcpy (&count, tpl, sizeof (gint32));
          for (int i = 0; i < count && i < MAFP_ENROLL_STAGES; i++)
            {
              const guint8 *sample = tpl + MAFP_TPL_HDR_SZ + i * MAFP_TPL_SAMPLE_SZ;
              if (mafp_match_score (norm8, sample) >= MAFP_MATCH_THRESH)
                { matched_print = p; goto id_done; }
            }
        }
id_done:
      fpi_device_identify_report (FP_DEVICE (self), matched_print, NULL, NULL);
      fpi_device_identify_complete (FP_DEVICE (self), NULL);
    }
  return;

canceled:
  if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      fpi_device_verify_report (FP_DEVICE (self), FPI_MATCH_ERROR, NULL,
        fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
      fpi_device_verify_complete (FP_DEVICE (self), NULL);
    }
  else
    {
      fpi_device_identify_report (FP_DEVICE (self), NULL, NULL,
        fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
      fpi_device_identify_complete (FP_DEVICE (self), NULL);
    }
}

/* ─── worker thread ──────────────────────────────────────────────── */

static gpointer
mafp_worker (gpointer data)
{
  FpiDeviceMafp *self = FPI_DEVICE_MAFP (data);

  while (TRUE)
    {
      g_mutex_lock (&self->lock);
      while (!self->has_work && !self->exit_flag)
        g_cond_wait (&self->cond, &self->lock);

      if (self->exit_flag)
        { g_mutex_unlock (&self->lock); break; }

      self->has_work = FALSE;
      self->canceled = FALSE;
      void (*func)(FpiDeviceMafp *) = self->run_func;
      g_mutex_unlock (&self->lock);

      if (func)
        func (self);
    }
  return NULL;
}

static void
mafp_dispatch (FpiDeviceMafp *self, void (*func)(FpiDeviceMafp *))
{
  g_mutex_lock (&self->lock);
  self->run_func = func;
  self->has_work = TRUE;
  self->canceled = FALSE;
  g_cond_signal (&self->cond);
  g_mutex_unlock (&self->lock);
}

/* ─── FpDevice callbacks ─────────────────────────────────────────── */

static void
mafp_open (FpDevice *dev)
{
  FpiDeviceMafp *self = FPI_DEVICE_MAFP (dev);
  const char *path = fpi_device_get_udev_data (dev, FPI_DEVICE_UDEV_SUBTYPE_SPIDEV);

  fp_info ("opening %s", path ? path : "(null)");

  if (!path)
    {
      fpi_device_open_complete (dev,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "no spidev path"));
      return;
    }

  self->spi_fd = open (path, O_RDWR);
  if (self->spi_fd < 0)
    {
      fpi_device_open_complete (dev,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                  "open %s: %s", path, g_strerror (errno)));
      return;
    }

  guint8 mode = SPI_MODE_0;
  guint8 bpw = 8;
  guint32 speed = MAFP_SPI_SPEED;
  ioctl (self->spi_fd, SPI_IOC_WR_MODE, &mode);
  ioctl (self->spi_fd, SPI_IOC_WR_BITS_PER_WORD, &bpw);
  ioctl (self->spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);

  /* Verify chip */
  if (!mafp_fp36_reset (self))
    {
      close (self->spi_fd); self->spi_fd = -1;
      fpi_device_open_complete (dev,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "chip not responding"));
      return;
    }

  gint id = mafp_set_reg (self, 0x04, 0x00);
  fp_info ("chip ID=0x%02x", id);
  if (id != MAFP_CHIPID_FP36)
    {
      close (self->spi_fd); self->spi_fd = -1;
      fpi_device_open_complete (dev,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                  "unsupported chip 0x%02x", id));
      return;
    }

  /* Allocate buffers */
  self->bg_frame   = g_malloc0 (MAFP_FRAME_BYTES);
  self->cur_frame  = g_malloc0 (MAFP_FRAME_BYTES);
  self->stab_frame = g_malloc0 (MAFP_FRAME_BYTES);
  self->detect_ref = g_malloc0 (MAFP_FRAME_BYTES);
  self->enhanced   = g_new0 (guint16, MAFP_ENHANCED_PIXELS);
  self->spi_buf    = g_malloc0 (MAFP_RAW_READ_SZ);

  /* Start worker */
  g_mutex_init (&self->lock);
  g_cond_init (&self->cond);
  self->exit_flag = FALSE;
  self->worker = g_thread_new ("mafp", mafp_worker, self);

  fpi_device_open_complete (dev, NULL);
}

static void
mafp_close (FpDevice *dev)
{
  FpiDeviceMafp *self = FPI_DEVICE_MAFP (dev);

  if (self->worker)
    {
      g_mutex_lock (&self->lock);
      self->exit_flag = TRUE;
      g_cond_signal (&self->cond);
      g_mutex_unlock (&self->lock);
      g_thread_join (self->worker);
      self->worker = NULL;
    }
  g_mutex_clear (&self->lock);
  g_cond_clear (&self->cond);

  g_clear_pointer (&self->bg_frame, g_free);
  g_clear_pointer (&self->cur_frame, g_free);
  g_clear_pointer (&self->stab_frame, g_free);
  g_clear_pointer (&self->detect_ref, g_free);
  g_clear_pointer (&self->enhanced, g_free);
  g_clear_pointer (&self->spi_buf, g_free);

  if (self->spi_fd >= 0)
    { close (self->spi_fd); self->spi_fd = -1; }

  fpi_device_close_complete (dev, NULL);
}

static void mafp_enroll (FpDevice *dev) { mafp_dispatch (FPI_DEVICE_MAFP (dev), mafp_enroll_run); }
static void mafp_verify (FpDevice *dev) { mafp_dispatch (FPI_DEVICE_MAFP (dev), mafp_verify_run); }

static void
mafp_cancel (FpDevice *dev)
{
  FpiDeviceMafp *self = FPI_DEVICE_MAFP (dev);
  g_mutex_lock (&self->lock);
  self->canceled = TRUE;
  g_mutex_unlock (&self->lock);
}

/* ─── GObject ────────────────────────────────────────────────────── */

static const FpIdEntry mafp_id_table[] = {
  { .udev_types = FPI_DEVICE_UDEV_SUBTYPE_SPIDEV,
    .spi_acpi_id = "MAFP8800", .driver_data = 0 },
  { .udev_types = 0 }
};

static void fpi_device_mafp_init (FpiDeviceMafp *self) { self->spi_fd = -1; }

static void
fpi_device_mafp_finalize (GObject *obj)
{
  FpiDeviceMafp *self = FPI_DEVICE_MAFP (obj);
  g_clear_pointer (&self->bg_frame, g_free);
  g_clear_pointer (&self->cur_frame, g_free);
  g_clear_pointer (&self->stab_frame, g_free);
  g_clear_pointer (&self->detect_ref, g_free);
  g_clear_pointer (&self->enhanced, g_free);
  g_clear_pointer (&self->spi_buf, g_free);
  if (self->spi_fd >= 0) close (self->spi_fd);
  G_OBJECT_CLASS (fpi_device_mafp_parent_class)->finalize (obj);
}

static void
fpi_device_mafp_class_init (FpiDeviceMafpClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id               = "mafp";
  dev_class->full_name        = "Microarray MAFP Fingerprint Sensor";
  dev_class->type             = FP_DEVICE_TYPE_UDEV;
  dev_class->id_table         = mafp_id_table;
  dev_class->scan_type        = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = MAFP_ENROLL_STAGES;

  dev_class->open     = mafp_open;
  dev_class->close    = mafp_close;
  dev_class->enroll   = mafp_enroll;
  dev_class->verify   = mafp_verify;
  dev_class->identify = mafp_verify;
  dev_class->cancel   = mafp_cancel;

  G_OBJECT_CLASS (klass)->finalize = fpi_device_mafp_finalize;

  fpi_device_class_auto_initialize_features (dev_class);
}
