
// MySQL 'capability' flags.
// http://dev.mysql.com/doc/internals/en/capability-flags.html#flag-CLIENT_PROTOCOL_41
//
// These are based on the values from /usr/include/mysql/mysql_com.h

#define CF_CLIENT_LONG_PASSWORD                   0x00000001UL
#define CF_CLIENT_FOUND_ROWS                      0x00000002UL
#define CF_CLIENT_LONG_FLAG                       0x00000004UL
#define CF_CLIENT_CONNECT_WITH_DB                 0x00000008UL
#define CF_CLIENT_NO_SCHEMA                       0x00000010UL
#define CF_CLIENT_COMPRESS                        0x00000020UL
#define CF_CLIENT_ODBC                            0x00000040UL
#define CF_CLIENT_LOCAL_FILES                     0x00000080UL
#define CF_CLIENT_IGNORE_SPACE                    0x00000100UL
#define CF_CLIENT_PROTOCOL_41                     0x00000200UL
#define CF_CLIENT_INTERACTIVE                     0x00000400UL
#define CF_CLIENT_SSL                             0x00000800UL
#define CF_CLIENT_IGNORE_SIGPIPE                  0x00001000UL
#define CF_CLIENT_TRANSACTIONS                    0x00002000UL
#define CF_CLIENT_RESERVED                        0x00004000UL
#define CF_CLIENT_SECURE_CONNECTION               0x00008000UL
#define CF_CLIENT_MULTI_STATEMENTS                0x00010000UL
#define CF_CLIENT_MULTI_RESULTS                   0x00020000UL
#define CF_CLIENT_PS_MULTI_RESULTS                0x00040000UL
#define CF_CLIENT_PLUGIN_AUTH                     0x00080000UL
#define CF_CLIENT_CONNECT_ATTRS                   0x00100000UL
#define CF_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA  0x00200000UL
#define CF_CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS    0x00400000UL
#define CF_CLIENT_SESSION_TRACK                   0x00800000UL
#define CF_CLIENT_DEPRECATE_EOF                   0x01000000UL
#define CF_CLIENT_SSL_VERIFY_SERVER_CERT          0x40000000UL
#define CF_CLIENT_REMEMBER_OPTIONS                0x80000000UL


// Server status flags; these are communicated back to the client in
// the OK and ERR packet types.
// http://dev.mysql.com/doc/internals/en/status-flags.html
#define SF_SERVER_STATUS_IN_TRANS              0x0001
#define SF_SERVER_STATUS_AUTOCOMMIT            0x0002
#define SF_SERVER_MORE_RESULTS_EXISTS          0x0008
#define SF_SERVER_STATUS_NO_GOOD_INDEX_USED    0x0010
#define SF_SERVER_STATUS_NO_INDEX_USED         0x0020
#define SF_SERVER_STATUS_CURSOR_EXISTS         0x0040
#define SF_SERVER_STATUS_LAST_ROW_SENT         0x0080
#define SF_SERVER_STATUS_DB_DROPPED            0x0100
#define SF_SERVER_STATUS_NO_BACKSLASH_ESCAPES  0x0200
#define SF_SERVER_STATUS_METADATA_CHANGED      0x0400
#define SF_SERVER_QUERY_WAS_SLOW               0x0800
#define SF_SERVER_PS_OUT_PARAMS                0x1000
#define SF_SERVER_STATUS_IN_TRANS_READONLY     0x2000
#define SF_SERVER_SESSION_STATE_CHANGED        0x4000

