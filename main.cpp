#include <cstdlib>
#include <sys/time.h>
#include <sys/resource.h>

#include <iostream>

#include "common.hpp"
#include "application.hpp"


int main(int, char *[]) {
	neosystem::util::set_rlimit_core();

	application app;
	app.run();
	return 0;
}
