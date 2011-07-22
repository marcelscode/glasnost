#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sstream>

#include "tools.h"

using namespace std;

// Do not buffer output!
void mprintf(const char *format, ...){
  char buffer[4096];
  va_list ap;
  va_start (ap, format);
  vsnprintf(buffer, sizeof(buffer), format, ap);
  buffer[sizeof(buffer)-1] = 0;
  write(STDOUT_FILENO, buffer, strlen(buffer));
  va_end (ap);
}

long long getTimeMicros(){
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000000LL + tv.tv_usec;
}

/**
 * Calc the timeout to a given end time
 */
void calcTimeout(const struct timeval *tend, struct timeval *timeout){
	assert(timeout != NULL && tend != NULL);

	gettimeofday(timeout, NULL);
	timeout->tv_sec = tend->tv_sec - timeout->tv_sec;
	timeout->tv_usec = tend->tv_usec - timeout->tv_usec;

	if(timeout->tv_usec < 0){
		timeout->tv_usec += 1000000;
		timeout->tv_sec -= 1;
	}
	if(timeout->tv_sec < 0){
		timeout->tv_sec = 0;
		timeout->tv_usec = 0;
	}
}

/**
 * Output the difference between t1 and t2 with t2 being later than t1
 */
void timeDiff(const struct timeval *t1, const struct timeval *t2, struct timeval *diff){
	diff->tv_sec = t2->tv_sec - t1->tv_sec;
	diff->tv_usec = t2->tv_usec - t1->tv_usec;

	while(diff->tv_usec < 0){
		diff->tv_usec += 1000000;
		diff->tv_sec -= 1;
	}

	if(diff->tv_sec < 0){
		diff->tv_sec = 0;
		diff->tv_usec = 0;
		warn(stderr, "timeDiff: t1 appears to be later than t2. Setting time difference to zero.");
		// warn(stderr, "timeDiff: %d.%d %d.%d", t1->tv_sec, t1->tv_usec, t2->tv_sec, t2->tv_usec);
	}
}

/**
 * Set a socket to be non-blocking
 */
void setNonblocking(int fd){
  int flags = fcntl(fd, F_GETFL, &flags);
  if (flags>=0) {
    flags |= O_NONBLOCK;

    int err = fcntl(fd, F_SETFL, flags);
    if (err<0)
      log(stdout, "Cannot set socket %d to nonblocking (errno=%d)", fd, errno);
//    else
//      log(stdout, "Socket %d set to nonblocking", fd);
  } else {
    log(stdout, "Cannot get socket flags for %d (errno=%d)", fd, errno);
  }
}

// converts an integer into a string
string intToStr(int n)
{
  ostringstream oss;
  oss << n;
  return oss.str();
}

// converts an unsigned integer into a string
string intToStr(unsigned int n)
{
  ostringstream oss;
  oss << n;
  return oss.str();
}

bool isAlphaNumeric(const std::string& str)
{
  for (string::const_iterator i = str.begin(); i != str.end(); ++i) 
    if (!isalnum(*i)) 
      return false;
	
  return true;

}

// return true iff str comprises only digits
bool isDigitString(const string& str)
{
  for (string::const_iterator i = str.begin(); i != str.end(); ++i) 
    if (!isdigit(*i)) 
      return false;
	
  return true;
}


/**
 * Remove leading and trailing whitespace (including tabs)
 */
void trim(string& line) {

  size_t first_not_ws = line.find_first_not_of("\t \r");
  line.erase(0, first_not_ws);
  
  size_t last_not_ws = line.find_last_not_of("\t \r");
  line.erase(last_not_ws + 1);
  
}

