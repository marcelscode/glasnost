#ifndef TOOLS_H_
#define TOOLS_H_

#include <string>

#define panic(a...) do { fprintf(stderr, a); fprintf(stderr, "\n"); exit(1); } while (0)
#define log(a,b...) do { fprintf(a, "%lld ", (getTimeMicros()/1000LL)); fprintf(a, b); fprintf(a, "\n"); fflush(a); } while (0)
#define error(a,b...) do { fprintf(a, "%lld ", (getTimeMicros()/1000LL)); fprintf(a, "ERROR: "); fprintf(a, b); fprintf(a, "\n"); fflush(a); } while (0)
#define warn(a,b...) do { fprintf(a, "%lld ", (getTimeMicros()/1000LL)); fprintf(a, "WARNING: "); fprintf(a, b); fprintf(a, "\n"); fflush(a); } while (0)
//#define debug(a,b...) do { fprintf(a, "%lld ", (getTimeMicros()/1000LL)); fprintf(a, "DEBUG: "); fprintf(a, b); fprintf(a, "\n"); fflush(a); } while (0)
#define debug(a,b...)

#define MAX(a, b) (a > b ? a : b)
#define MIN(a, b) (a < b ? a : b)

void mprintf(const char *format, ...);
long long getTimeMicros();
void calcTimeout(const struct timeval *tend, struct timeval *timeout);
void timeDiff(const struct timeval *t1, const struct timeval *t2, struct timeval *diff);
void setNonblocking(int fd);
std::string intToStr(int n);
std::string intToStr(unsigned int n);
bool isDigitString(const std::string& str);
bool isAlphaNumeric(const std::string& str);
void trim(std::string& line);

#endif /* TOOLS_H_ */
