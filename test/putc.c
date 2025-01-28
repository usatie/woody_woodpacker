#include <unistd.h>
int main() {
	char c = 'H';
	write(1, &c, 1);
	return 0;
}
