#include <iostream> 
#include <fstream> 
#include <string> 
#include <cstring>  
#include <cstdio>
#include <iomanip>
#include <cstdlib>
#include <cmath>
#include <sys/time.h>
#include <time.h>
#include <gmp.h>
#include <assert.h>

using namespace std;

int main() 
{
	// initialize variables
	mpz_t l, rand;
	unsigned long seed;
	seed = time(NULL);
	// perform inits to create variable pointers with 0 values
	mpz_init(rand);
	mpz_init(l);
	
	// calculate random number floor (at least 100 digits long)
	mpz_ui_pow_ui(l, 10, 100);
	// initialize the random number seed
	gmp_randstate_t rstate;
	// initialize state for a Mersenne Twister algorithm
	gmp_randinit_mt(rstate);
	// create the generatero seed for random number engine
	gmp_randseed_ui(rstate, seed);
	
	do {
		// generate number between 0 and 2^340 (~10^103 in base 2)
		mpz_urandomb(rand, rstate, 340);
		// add base to generated number, should now be between 10^100 and 2*10^100
		mpz_add(rand, rand, l);
	
	} while ((mpz_probab_prime_p(rand, 25)) == 0);
	
	// output number after a prime is generated
	mpz_out_str(stdout,10,rand);
	cout << endl;
	
	// cleanup ops
	gmp_randclear(rstate);
	mpz_clear(l);
	mpz_clear(rand);
}