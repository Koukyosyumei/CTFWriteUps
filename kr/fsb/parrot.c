#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
void show_flag() {
    FILE *fp;
    char *flag = (char *)malloc(64);
    fp = fopen("flag", "r");
    fread(flag, 1, 63, fp);
    fclose(fp);
    printf(flag);
    free(flag);
}
int main(void) {
    int i;

    for (i = 0; i < 3; i++) {
        scanf("%31s", buf);
        printf(buf);
    }
    if (i == 0) {
        show_flag();
    } else {
        exit(1);
    }

    return 0;
}
