#include <sys/stat.h>
#include <time.h>
#include <stdbool.h>

bool fileViewer(const char *path, double *timeDiff) {
    struct stat statbuf;
    if (stat(path, &statbuf) == 0) {
        time_t now = time(NULL);
        if (timeDiff != NULL) {
            *timeDiff = difftime(now, statbuf.st_mtime); // Modification time difference
        }
        return true;
    }
    return false;
}
