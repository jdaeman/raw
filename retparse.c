#include <stdio.h>
#include <string.h>

int main(int argc, char ** argv)
{
	FILE * fp;
	char buf[3][64];
	int len;

	if (argc == 1 || (fp = fopen(argv[1], "rt")))
	{
		if (argc == 1)
			printf("No param\n");
		else
			perror("fopen");
		return 0;
	}

	while (feof(fp) == 0)
	{
		memset(buf, 0, sizeof(buf));

		fscanf(fp, "%s\t%s\t%s\n", buf[0], buf[1], buf[2]);

		//buf[1] has "[11:22:33:44:55:66]"
		//so, remove '[' and ']'

		len = strlen(buf[1]);
		buf[1][len - 1] = 0;
		printf("%s\n", buf[1] + 1);
	}	

	fclose(fp);

	return 0;
}

