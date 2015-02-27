

// These form a linked list in the main Config object.
// Note that these are never deleted - they're just set up at init time
// and kept around for the life of the process.  (So no destructor is implemented)
class DatabaseBackendConfig {
public:
  const char * hostname;
  int port;
  const char * username;
  const char * password;
  const char * apparent_database_name;
  const char * actual_database_name;

  int max_idle_connection_lease_time;
  int max_connection_lease_time;
  int database_connect_timeout;
  bool use_nonblocking_connect;
  int database_query_timeout;
  int pending_lease_request_timeout;
  int max_database_connection_lifetime;
  int connection_pool_size;
  int character_set_code;

  DatabaseBackendConfig * next;

public:
  DatabaseBackendConfig();

  const char * validate() const;
};


class Config {
public:
  // Runtime options.
  int listen_on_port;
  int max_clients;
  int max_client_input_backlog;
  int delay_milliseconds_between_db_connections;
  const char * server_version;
  bool cache_schema;
  bool simulate_busy_dbs;
  bool use_nonblocking_dns;
  int dns_cache_time;
  int clean_shutdown_timeout;
  bool require_client_auth;
  bool verbose;
  const char * logfile_name;
  bool use_syslog;
  const char * syslog_ident;
  bool use_mfp_syslog_format;
  const char * default_apparent_database_name;

  // Statsd options.  We'll try to use statsd if statsd_hostname was provided.
  const char * statsd_hostname;
  int statsd_port;
  const char * statsd_key_prefix;
  int statsd_send_interval;

  // Default settings to use for database connection pools.
  // These can be overridden per-pool in the config file.
  DatabaseBackendConfig database_defaults;

  // linked list of database backend configs
  DatabaseBackendConfig * database_backend_config_list;
  int database_backend_config_count;

public:
  Config();

  void add_database_backend_config(DatabaseBackendConfig * backend_config);
};


extern Config * global_config;


void parse_config_files(const char * filenames[], int filename_count);


