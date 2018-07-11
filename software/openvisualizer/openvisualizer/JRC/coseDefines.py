# COSE key labels
KEY_LABEL_KTY                          = 1
KEY_LABEL_KID                          = 2
KEY_LABEL_ALG                          = 3
KEY_LABEL_KEYOPS                       = 4
KEY_LABEL_BASEIV                       = 5
KEY_LABEL_K                            = -1
KEY_LABEL_CLIENT_ID                    = 6      # value TBD by IANA, registered in draft-ietf-ace-oscore-profile-02
KEY_LABEL_SERVER_ID                    = 7      # value TBD by IANA, registered in draft-ietf-ace-oscore-profile-02
KEY_LABEL_KDF                          = 8      # value TBD by IANA, registered in draft-ietf-ace-oscore-profile-02
KEY_LABEL_SLT                          = 9      # value TBD by IANA, registered in draft-ietf-ace-oscore-profile-02
KEY_LABEL_ALL = [
    KEY_LABEL_KTY,
    KEY_LABEL_KID,
    KEY_LABEL_ALG,
    KEY_LABEL_KEYOPS,
    KEY_LABEL_BASEIV,
    KEY_LABEL_K,
    KEY_LABEL_CLIENT_ID,
    KEY_LABEL_SERVER_ID,
    KEY_LABEL_KDF,
    KEY_LABEL_SLT,
]

# COSE key values
KEY_VALUE_OKP                          = 1
KEY_VALUE_EC2                          = 2
KEY_VALUE_SYMMETRIC                    = 4
KEY_VALUE_ALL = [
    KEY_VALUE_OKP,
    KEY_VALUE_EC2,
    KEY_VALUE_SYMMETRIC,
]

ALG_AES_CCM_16_64_128                  = 10
ALG_AES_CCM_16_64_256                  = 11
ALG_AES_CCM_64_64_128                  = 12
ALG_AES_CCM_64_64_256                  = 13
ALG_AES_CCM_16_128_128                 = 30
ALG_AES_CCM_16_128_256                 = 31
ALG_AES_CCM_64_128_128                 = 32
ALG_AES_CCM_64_128_256                 = 33

ALG_AES_CCM_ALL = [
    ALG_AES_CCM_16_64_128,
    ALG_AES_CCM_16_64_256,
    ALG_AES_CCM_64_64_128,
    ALG_AES_CCM_64_64_256,
    ALG_AES_CCM_16_128_128,
    ALG_AES_CCM_16_128_256,
    ALG_AES_CCM_64_128_128,
    ALG_AES_CCM_64_128_256,
]

COMMON_HEADER_PARAMETERS_ALG                = 1
COMMON_HEADER_PARAMETERS_CRIT               = 2
COMMON_HEADER_PARAMETERS_CONTENT_TYPE       = 3
COMMON_HEADER_PARAMETERS_KID                = 4
COMMON_HEADER_PARAMETERS_IV                 = 5
COMMON_HEADER_PARAMETERS_PIV                = 6
COMMON_HEADER_PARAMETERS_COUNTER_SIGNATURE  = 7

COMMON_HEADER_PARAMETERS_ALL = [
    COMMON_HEADER_PARAMETERS_ALG,
    COMMON_HEADER_PARAMETERS_CRIT,
    COMMON_HEADER_PARAMETERS_CONTENT_TYPE,
    COMMON_HEADER_PARAMETERS_KID,
    COMMON_HEADER_PARAMETERS_IV,
    COMMON_HEADER_PARAMETERS_PIV,
    COMMON_HEADER_PARAMETERS_COUNTER_SIGNATURE,
]
