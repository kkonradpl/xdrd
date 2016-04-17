#ifndef XDR_PROTOCOL_H_
#define XDR_PROTOCOL_H_

#define XDR_P_ARDUINO_INIT_TIME 1750

#define XDR_P_STARTUP  'x'
#define XDR_P_SHUTDOWN 'X'

#define XDR_P_MODE 'M'
#define XDR_P_MODE_DEFAULT 0

#define XDR_P_VOLUME 'Y'
#define XDR_P_VOLUME_DEFAULT 100

#define XDR_P_DEEMPHASIS 'D'
#define XDR_P_DEEMPHASIS_DEFAULT 0

#define XDR_P_AGC 'A'
#define XDR_P_AGC_DEFAULT 2

#define XDR_P_FILTER 'F'
#define XDR_P_FILTER_DEFAULT -1

#define XDR_P_ANTENNA 'Z'
#define XDR_P_ANTENNA_DEFAULT 0

#define XDR_P_GAIN 'G'
#define XDR_P_GAIN_DEFAULT 0

#define XDR_P_TUNE 'T'
#define XDR_P_TUNE_DEFAULT 87500

#define XDR_P_DAA 'V'
#define XDR_P_DAA_DEFAULT 0

#define XDR_P_SQUELCH 'Q'
#define XDR_P_SQUELCH_DEFAULT 0

#define XDR_P_ROTATOR 'C'
#define XDR_P_ROTATOR_DEFAULT 0

#define XDR_P_PI  'P'
#define XDR_P_RDS 'R'

#define XDR_TCP_DEFAULT_PORT 7373
#define XDR_TCP_SALT_LENGTH    16

#endif
