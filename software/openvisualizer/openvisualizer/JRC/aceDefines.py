# constants from draft-ietf-ace-oauth-authz-13

# Figure 12 draft-ietf-ace-oauth-authz-13: CBOR mappings used in token requests
ACE_PARAMETERS_LABELS_AUD                   = 3         # text string
ACE_PARAMETERS_LABELS_CLIENT_ID             = 8         # text string
ACE_PARAMETERS_LABELS_CLIENT_SECRET         = 9         # byte string
ACE_PARAMETERS_LABELS_RESPONSE_TYPE         = 10        # text string
ACE_PARAMETERS_LABELS_REDIRECT_URI          = 11        # text string
ACE_PARAMETERS_LABELS_SCOPE                 = 12        # text or byte string
ACE_PARAMETERS_LABELS_STATE                 = 13        # text string
ACE_PARAMETERS_LABELS_CODE                  = 14        # byte string
ACE_PARAMETERS_LABELS_ERROR                 = 15        # unsigned integer
ACE_PARAMETERS_LABELS_ERROR_DESCRIPTION     = 16        # text string
ACE_PARAMETERS_LABELS_ERROR_URI             = 17        # text string
ACE_PARAMETERS_LABELS_GRANT_TYPE            = 18        # unsigned integer
ACE_PARAMETERS_LABELS_ACCESS_TOKEN          = 19        # byte string
ACE_PARAMETERS_LABELS_TOKEN_TYPE            = 20        # unsigned integer
ACE_PARAMETERS_LABELS_EXPIRES_IN            = 21        # unsigned integer
ACE_PARAMETERS_LABELS_USERNAME              = 22        # text string
ACE_PARAMETERS_LABELS_PASSWORD              = 23        # text string
ACE_PARAMETERS_LABELS_REFRESH_TOKEN         = 24        # byte string
ACE_PARAMETERS_LABELS_CNF                   = 25        # map
ACE_PARAMETERS_LABELS_PROFILE               = 26        # unsigned integer
ACE_PARAMETERS_LABELS_RS_CNF                = 31        # map


#  Figure 11 from draft-ietf-ace-oauth-authz-13: CBOR abbreviations for common grant types
ACE_CBOR_ABBREVIATIONS_PASSWORD             = 0
ACE_CBOR_ABBREVIATIONS_AUTHORIZATION_CODE   = 1
ACE_CBOR_ABBREVIATIONS_CLIENT_CREDENTIALS   = 2
ACE_CBOR_ABBREVIATIONS_REFRESH_TOKEN        = 3

ACE_ACCESS_TOKEN_TYPE_BEARER                = 1
ACE_ACCESS_TOKEN_TYPE_POP                   = 2

# from https://tools.ietf.org/html/draft-ietf-ace-cwt-proof-of-possession-03#section-3.1
ACE_CWT_CNF_COSE_KEY                        = 1
ACE_CWT_CNF_ENCRYPTED_COSE_KEY              = 2
ACE_CWT_CNF_KID                             = 3