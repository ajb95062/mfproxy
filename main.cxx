

#include "main.h"


const char * program_name = 0;
static const char * config_filenames[10];
static int config_filename_count = 0;


static void parse_commandline_args(int argc, char * argv[]);
static void really_log_message(int priority, const char * format, va_list args);
static void really_log_message_to_file(FILE * file, int priority, const char * format, va_list args);
static void really_log_message_to_syslog(int priority, const char * format, va_list args);
static const char * syslog_priority_to_string(int priority);
static void format_log_message_for_mfp(char * buf, size_t buflen, int priority, const char * message);


int main(int argc, char * argv[]) {
  program_name = argv[0];
  srand(time(0));
  setlinebuf(stdout);
  setlinebuf(stderr);

  // Process commandline arguments and config files.
  parse_commandline_args(argc, argv);
  if(config_filename_count == 0)
    config_filenames[config_filename_count++] = "proxy.cfg";
  parse_config_files(config_filenames, config_filename_count);
  
  // Start up the server.
  current_server = new Server;
  current_server->startup();  // NOTE: never returns
  
  return 0;
}


static void parse_commandline_args(int argc, char * argv[]) {
  int ch;
  bool show_help = false;
  char * s;

  while((ch = getopt(argc, argv, "c:h")) != -1) {
    switch(ch) {
    case 'c':  // config file name
      if(config_filename_count < (int)arraysize(config_filenames)) {
        s = new char[strlen(optarg)+1];  // small memory leak, doesn't matter
        strcpy(s, optarg);
        config_filenames[config_filename_count++] = s;
      }
      else
        fprintf(stderr, "Warning: too many config files specified with -c options.  Ignoring the rest.\n");
      break;

    case 'h':
      show_help = true;
      break;

    default:
      break;
    }
  }

  if(show_help) {
    fprintf(stderr,
            "Usage: %s [-c config_file] [-h]\n"
            "    -c config_file         Path to configuration file (default: proxy.cfg in current directory)\n"
            "                           Multiple -c options may be specified if desired.\n"
            "    -h                     Show this help message\n",
            argv[0]);
    exit(1);
  }
}


// Based on: http://www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html
// Subtract the ‘struct timeval’ values x and y, storing the result in *result.
void timeval_subtract(struct timeval * result, struct timeval * x, struct timeval * y) {
  // Perform the carry for the later subtraction by updating y.
  if(x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if(x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (x->tv_usec - y->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  // Compute the time remaining to wait.  tv_usec is certainly positive.
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;
}


// Get the number of seconds in a timeval (assumed to be a time interval) as a floating-point value.
double timeval_seconds(const struct timeval * tv) {
  return (double)tv->tv_sec + tv->tv_usec / 1000000.0;
}


void log_message(const char * format, ...) {
  va_list args;
  va_start(args, format);
  really_log_message(LOG_NOTICE, format, args);
  va_end(args);
}


void log_error_message(const char * format, ...) {
  va_list args;
  va_start(args, format);
  really_log_message(LOG_ERR, format, args);
  va_end(args);
}


void log_debug_message(const char * format, ...) {
  va_list args;
  va_start(args, format);
  if(global_config->verbose)
    really_log_message(LOG_DEBUG, format, args);
  va_end(args);
}


void panic(const char * format, ...) {
  va_list args;
  va_start(args, format);
  fprintf(stderr, "Panic: ");
  vfprintf(stderr, format, args);
  fprintf(stderr, "\n");
  va_end(args);
  abort();
}


void not_yet_implemented() {
  panic("code not yet implemented");
}


static void really_log_message(int priority, const char * format, va_list args) {
  if(global_config->use_syslog)
    really_log_message_to_syslog(priority, format, args);
  else {
    FILE * logfile;
    if(current_server && current_server->logfile)
      logfile = current_server->logfile;
    else
      logfile = stdout;
    really_log_message_to_file(logfile, priority, format, args);
  }
}


static void really_log_message_to_file(FILE * file, int priority, const char * format, va_list args) {
  // Get the time string without trailing newline.
  time_t current_time = time(0);
  char timebuf[80];
  strcpy(timebuf, ::asctime(::localtime(&current_time)));
  if(timebuf[strlen(timebuf)-1] == '\n')
    timebuf[strlen(timebuf)-1] = '\0';

  fprintf(file, "[%s] (%s): ", timebuf, syslog_priority_to_string(priority));
  vfprintf(file, format, args);
  fprintf(file, "\n");
}


static void really_log_message_to_syslog(int priority, const char * format, va_list args) {
  if(global_config->use_mfp_syslog_format) {
    // Use MyFitnessPal internal syslog format for systemwide log aggregation.
    char message_buf[10000], final_buf[10000];
    vsnprintf(message_buf, sizeof(message_buf), format, args);
    format_log_message_for_mfp(final_buf, sizeof(final_buf), priority, message_buf);
    syslog(priority, "%s", final_buf);
  }
  else {
    // Pass the message directly to syslog.
    vsyslog(priority, format, args);
  }
}


// Convert a syslog priority level into a printable string.
static const char * syslog_priority_to_string(int priority) {
  switch(priority) {
  case LOG_EMERG: return "EMERG";
  case LOG_ALERT: return "ALERT";
  case LOG_CRIT: return "CRIT";
  case LOG_ERR: return "ERR";
  case LOG_WARNING: return "WARNING";
  case LOG_NOTICE: return "NOTICE";
  case LOG_INFO: return "INFO";
  case LOG_DEBUG: return "DEBUG";
  default: return "UNKNOWN";
  }
}


static void format_log_message_for_mfp(char * buf, size_t buflen, int priority, const char * message) {
  // Get the time as an ISO8601 string.
  time_t now = time(0);
  char timebuf[100];
  // Not sure what is up with the ,000 part (milliseconds I assume).  Nonstandard?
  strftime(timebuf, sizeof(timebuf), "%F %T,000", gmtime(&now));

  // Generate the MFP-specific syslog format.  Much of this format assumes that it's directly
  // associated with a web/client request, hence all the empty "" fields.
  // NOTE: MFP syslog format has a redundant initial field specifying the "service name".
  // This already comes with syslog entries, but we have to explicitly emit it here too.
  snprintf(buf, buflen,
           "%s: %s - \"%s\" - \"\" - \"\" - \"\" - \"\" - \"\" - \"\" - %s",
           global_config->syslog_ident, timebuf,
           syslog_priority_to_string(priority), message);

  // NOTE: Newlines are not allowed in the log message.  Convert any newlines into spaces.
  int len = strlen(buf);
  loopi(len)
    if(buf[i] == '\n' || buf[i] == '\r')
      buf[i] = ' ';
}
