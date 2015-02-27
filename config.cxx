

// Config file parsing using liblcfg (in lcfg_static.c).

#include "main.h"


Config * global_config = 0;

static const char * current_config_filename_being_parsed = 0;


static void scan_root(const struct lcfgx_tree_node * root_node);
static void scan_options(const struct lcfgx_tree_node * node);
static void scan_database_backends(const struct lcfgx_tree_node * node);
static void scan_database_backend_config(const struct lcfgx_tree_node * node, DatabaseBackendConfig * db_config);

static const char * extract_string(const lcfgx_tree_node * node);
static uint32_t extract_integer(const lcfgx_tree_node * node);
static bool extract_boolean(const lcfgx_tree_node * node);
static void config_file_error(const char * format, ...);



// If there are any errors with the config file(s), they are printed
// to stderr and the program just exits.
void parse_config_files(const char * filenames[], int filename_count) {
  global_config = new Config;

  loopi(filename_count) {
    FILE * file = fopen(filenames[i], "r");
    current_config_filename_being_parsed = filenames[i];
    if(!file)
      config_file_error("Could not open file.");

    struct lcfg * cfg = lcfg_new(filenames[i]);
    if(lcfg_parse(cfg) != lcfg_status_ok)
      config_file_error("Parse error (%s).", lcfg_error_get(cfg));

    struct lcfgx_tree_node * cfg_tree = lcfgx_tree_new(cfg);

    scan_root(cfg_tree);
  
    lcfgx_tree_delete(cfg_tree);
    lcfg_delete(cfg);
  }

  current_config_filename_being_parsed = 0;
  if(global_config->database_backend_config_count == 0)
    config_file_error("No database_backend found in config file(s).");
  if(global_config->default_apparent_database_name == 0)
    config_file_error("default_apparent_database_name setting is required.");
}


DatabaseBackendConfig::DatabaseBackendConfig() {
  hostname = 0;
  port = 3306;
  username = 0;
  password = 0;
  apparent_database_name = 0;
  actual_database_name = 0;
  max_idle_connection_lease_time = -1;
  max_connection_lease_time = -1;
  database_connect_timeout = -1;
  use_nonblocking_connect = true;
  database_query_timeout = -1;
  pending_lease_request_timeout = -1;
  max_database_connection_lifetime = -1;
  connection_pool_size = 5;
  character_set_code = 33;
}


// If there's an error, returns a short string describing the problem.
// If it's OK, returns null.
const char * DatabaseBackendConfig::validate() const {
  if(!hostname) return "missing hostname field";
  if(!username) return "missing username field";
  if(!password) return "missing password field";
  if(!apparent_database_name) return "missing apparent_database_name field";
  if(!actual_database_name) return "missing actual_database_name field";
  return 0;
}


Config::Config() {
  database_backend_config_list = 0;
  database_backend_config_count = 0;

  // Default config options:
  listen_on_port = 2345;
  max_clients = 1000;
  max_client_input_backlog = -1;
  delay_milliseconds_between_db_connections = 0;
  server_version = "5.6.20-68.0-56-logG";
  cache_schema = false;
  simulate_busy_dbs = false;
  use_nonblocking_dns = true;
  dns_cache_time = 10;
  clean_shutdown_timeout = 10;
  require_client_auth = false;
  verbose = false;
  logfile_name = 0;
  use_syslog = false;
  syslog_ident = "mfproxy";
  use_mfp_syslog_format = false;
  default_apparent_database_name = 0;

  statsd_hostname = 0;
  statsd_port = 8125;
  statsd_key_prefix = "mfproxy";
  statsd_send_interval = 2;
}


void Config::add_database_backend_config(DatabaseBackendConfig * backend_config) {
  backend_config->next = database_backend_config_list;
  database_backend_config_list = backend_config;
  database_backend_config_count++;
}


static void scan_root(const struct lcfgx_tree_node * root_node) {
  for(struct lcfgx_tree_node * node = root_node->value.elements; node; node = node->next) {
    const char * k = node->key;
    if(strcmp(k, "options") == 0 && node->type == lcfgx_map)
      scan_options(node->value.elements);
    else if(strcmp(k, "defaults") == 0 && node->type == lcfgx_map)
      scan_database_backend_config(node->value.elements, &global_config->database_defaults);
    else if(strcmp(k, "database_backends") == 0 && node->type == lcfgx_list)
      scan_database_backends(node->value.elements);
    else
      config_file_error("Unexpected key \"%s\" found.", k);
  }
}


static void scan_options(const struct lcfgx_tree_node * node) {
  Config * c = global_config;
  for(; node; node = node->next) {
    const char * k = node->key;
    if(strcmp(k, "listen_on_port") == 0)
      c->listen_on_port = extract_integer(node);
    else if(strcmp(k, "max_clients") == 0)
      c->max_clients = extract_integer(node);
    else if(strcmp(k, "max_client_input_backlog") == 0)
      c->max_client_input_backlog = extract_integer(node);
    else if(strcmp(k, "delay_milliseconds_between_db_connections") == 0)
      c->delay_milliseconds_between_db_connections = extract_integer(node);
    else if(strcmp(k, "server_version") == 0)
      c->server_version = extract_string(node);
    else if(strcmp(k, "cache_schema") == 0)
      c->cache_schema = extract_boolean(node);
    else if(strcmp(k, "simulate_busy_dbs") == 0)
      c->simulate_busy_dbs = extract_boolean(node);
    else if(strcmp(k, "use_nonblocking_dns") == 0)
      c->use_nonblocking_dns = extract_boolean(node);
    else if(strcmp(k, "dns_cache_time") == 0)
      c->dns_cache_time = extract_integer(node);
    else if(strcmp(k, "clean_shutdown_timeout") == 0)
      c->clean_shutdown_timeout = extract_integer(node);
    else if(strcmp(k, "require_client_auth") == 0)
      c->require_client_auth = extract_boolean(node);
    else if(strcmp(k, "verbose") == 0)
      c->verbose = extract_boolean(node);
    else if(strcmp(k, "logfile_name") == 0)
      c->logfile_name = extract_string(node);
    else if(strcmp(k, "use_syslog") == 0)
      c->use_syslog = extract_boolean(node);
    else if(strcmp(k, "syslog_ident") == 0)
      c->syslog_ident = extract_string(node);
    else if(strcmp(k, "use_mfp_syslog_format") == 0)
      c->use_mfp_syslog_format = extract_boolean(node);
    else if(strcmp(k, "default_apparent_database_name") == 0)
      c->default_apparent_database_name = extract_string(node);
    else if(strcmp(k, "statsd_hostname") == 0)
      c->statsd_hostname = extract_string(node);
    else if(strcmp(k, "statsd_port") == 0)
      c->statsd_port = extract_integer(node);
    else if(strcmp(k, "statsd_key_prefix") == 0)
      c->statsd_key_prefix = extract_string(node);
    else if(strcmp(k, "statsd_send_interval") == 0)
      c->statsd_send_interval = extract_integer(node);
    else
      fprintf(stderr, "Warning: unrecognized option \"%s\" in config file.  Ignoring.\n", k);
  }
}


static void scan_database_backends(const struct lcfgx_tree_node * node) {
  for(; node; node = node->next) {
    DatabaseBackendConfig * db_config = new DatabaseBackendConfig;

    if(node->type != lcfgx_map)
      config_file_error("Each database_backends section must be a key-value map.");

    // Initialize the new backend config from the global defaults.
    *db_config = global_config->database_defaults;
    
    scan_database_backend_config(node->value.elements, db_config);

    // Validate the config (only for the actual database backend config sections, not
    // the database defaults section).
    const char * error_message = db_config->validate();
    if(error_message)
      config_file_error("database_backend config %s.", error_message);
    
    global_config->add_database_backend_config(db_config);
  }
}


static void scan_database_backend_config(const struct lcfgx_tree_node * node, DatabaseBackendConfig * db_config) {
  for(; node; node = node->next) {
    const char * k = node->key;
    if(strcmp(k, "hostname") == 0)
      db_config->hostname = extract_string(node);
    else if(strcmp(k, "port") == 0)
      db_config->port = extract_integer(node);
    else if(strcmp(k, "username") == 0)
      db_config->username = extract_string(node);
    else if(strcmp(k, "password") == 0)
      db_config->password = extract_string(node);
    else if(strcmp(k, "apparent_database_name") == 0)
      db_config->apparent_database_name = extract_string(node);
    else if(strcmp(k, "actual_database_name") == 0)
      db_config->actual_database_name = extract_string(node);
    else if(strcmp(k, "database_name") == 0)
      db_config->apparent_database_name = db_config->actual_database_name = extract_string(node);
    else if(strcmp(k, "max_idle_connection_lease_time") == 0)
      db_config->max_idle_connection_lease_time = extract_integer(node);
    else if(strcmp(k, "max_connection_lease_time") == 0)
      db_config->max_connection_lease_time = extract_integer(node);
    else if(strcmp(k, "database_connect_timeout") == 0)
      db_config->database_connect_timeout = extract_integer(node);
    else if(strcmp(k, "use_nonblocking_connect") == 0)
      db_config->use_nonblocking_connect = extract_boolean(node);
    else if(strcmp(k, "database_query_timeout") == 0)
      db_config->database_query_timeout = extract_integer(node);
    else if(strcmp(k, "pending_lease_request_timeout") == 0)
      db_config->pending_lease_request_timeout = extract_integer(node);
    else if(strcmp(k, "max_database_connection_lifetime") == 0)
      db_config->max_database_connection_lifetime = extract_integer(node);
    else if(strcmp(k, "connection_pool_size") == 0)
      db_config->connection_pool_size = extract_integer(node);
    else if(strcmp(k, "character_set_code") == 0)
      db_config->character_set_code = extract_integer(node);
    else
      fprintf(stderr, "Warning: ignoring unexpected key \"%s\" database option in config file.\n", k);
  }
}


// Returns a freshly allocated, NUL-terminated string.
// If the string is of the form [[filename]], the referenced file's contents will be
// read in from disk and returned as the result instead.
static const char * extract_string(const lcfgx_tree_node * node) {
  char * s;
  
  if(node->type != lcfgx_string)
    config_file_error("Expected \"%s\" key to have a string or integer value.", node->key);

  s = new char[node->value.string.len + 1];
  memcpy(s, node->value.string.data, node->value.string.len);
  s[node->value.string.len] = '\0';

  // If the string is of the form [[filename]], read in the referenced filename
  // and use the file contents instead.  Any trailing whitespace will be stripped.
  int len = strlen(s);
  char * filename, * file_contents;
  FILE * file;
  long filesize;
  if(len >= 4 && s[0] == '[' && s[1] == '[' && s[len-2] == ']' && s[len-1] == ']') {
    // Remove the [[ ]] part.
    s[len-2] = '\0';
    filename = s+2;

    // If the "filename" has a : in it, use the stuff after the colon as a default value
    // if the file doesn't exist.
    char * default_value = 0, * colon_pos = strrchr(filename, ':');
    if(colon_pos) {
      default_value = colon_pos + 1;
      *colon_pos = '\0';
    }
    
    file = fopen(filename, "r");
    if(!file) {
      if(default_value) {
        char * default_value_dup = new char[strlen(default_value) + 1];
        strcpy(default_value_dup, default_value);
        delete [] s;
        return default_value_dup;
      }
      config_file_error("Referenced file [[%s]] could not be opened.", filename);
    }

    // Get the file size and make sure it's nothing excessive.
    fseek(file, 0, SEEK_END);
    filesize = ftell(file);
    fseek(file, 0, SEEK_SET);
    if(filesize <= 0)
      config_file_error("Referenced file [[%s]] is empty.", filename);
    else if(filesize > 10000)
      config_file_error("Referenced file [[%s]] is too large (%ld bytes).", filename, (long)filesize);

    // Read in the file's contents.
    file_contents = new char[filesize+1];
    size_t bytes_read = fread(file_contents, 1, filesize, file);
    if(bytes_read != (size_t)filesize)
      config_file_error("Error reading contents of referenced file [[%s]] (only got %ld bytes).",
                        filename, (long)bytes_read);
    file_contents[filesize] = '\0';
    fclose(file);

    // Strip trailing whitespace from file_contents.
    while(filesize > 0 && isspace(file_contents[filesize-1])) {
      file_contents[filesize-1] = '\0';
      filesize--;
    }

    delete [] s;
    return file_contents;
  }

  return s;
}


static uint32_t extract_integer(const lcfgx_tree_node * node) {
  const char * s = extract_string(node);
  uint32_t value = atol(s);
  delete [] s;
  return value;
}


static bool extract_boolean(const lcfgx_tree_node * node) {
  const char * s = extract_string(node);
  bool value = true;
  if(strcasecmp(s, "true") == 0 || strcasecmp(s, "yes") == 0)
    value = true;
  else if(strcasecmp(s, "false") == 0 || strcasecmp(s, "no") == 0)
    value = false;
  else
    config_file_error("Expected boolean value for \"%s\" field.", node->key);
  delete [] s;
  return value;
}


static void config_file_error(const char * format, ...) {
  va_list args;
  va_start(args, format);
  fprintf(stderr, "Error in config file");
  if(current_config_filename_being_parsed)
    fprintf(stderr, " \"%s\"", current_config_filename_being_parsed);
  fprintf(stderr, ": ");
  vfprintf(stderr, format, args);
  fprintf(stderr, "\n");
  va_end(args);
  exit(1);
}
