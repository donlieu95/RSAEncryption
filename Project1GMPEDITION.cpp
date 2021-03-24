#include <iostream> 
#include <bits/stdc++.h>
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

//CSCI 415, Computer Security
//Project 1
//Group 1
//Don Lieu, Andrew Hoeschen, Connor Downs, and Erik Gablenz
//Description: Simulate RSA Encryption

using namespace std;

bool isPrime(int n, int k)
//Test for primality using Miller-Rabin method.
{
	if (n % 2 == 0)
	{
		return false;
	}
	else
	{
		int rMax = log2(n-1);
		int r = rand() % rMax + 1;
		int d = (n-1) / ( pow(2,r));
		//Miller Test k times
		for (int i = 0; i < k; i++)
		{
			int a = rand() % (n-2) + 2;
			int tempX = floor(pow(a, d));
			int x = tempX % n;
			if ( (x != 1) || (x != n-1) )
			{
				for (int j = 0; j < (r-1); j++)
				{
					x = (x*x) % n;
					if (x == 1)
					{
						return false;
					}
					if (x == (n-1))
					{
						break;
					}
				}
			}
		}
		return true;
	}
}


//void encrypt(int p, int q, int e, int d, int numberConversion[], int size, ostream& outfile)
void encrypt(mpz_t mpzP, mpz_t mpzQ, mpz_t mpzE, int numberConversion[], int size, ostream& outfile)
{
	int trigraphCount = floor(size/3), totient, trigraphCalc;
	mpz_t mpzN;
	mpz_init(mpzN);
	
	
	mpz_mul(mpzN, mpzP, mpzQ);
	mpz_t mpzTrigraphs[trigraphCount];

	//Interpret each trigraph as a number in base 26
	for (int i = 0; i < trigraphCount; i++)
	{
		mpz_init(mpzTrigraphs[i]);
		trigraphCalc = (numberConversion[(i * 3)] * 26 * 26) + (numberConversion[((i * 3) + 1)] * 26) + numberConversion[((i * 3) + 2)];
		mpz_set_ui(mpzTrigraphs[i], trigraphCalc);
		
	}

	//Encrypted trigraph array
	mpz_t mpzETrigraphs[trigraphCount];
	
	for (int i = 0; i < trigraphCount; i++)
	{
		//Encipher each plaintext trigraph code using C = M^e mod n
		
		mpz_init(mpzETrigraphs[i]);
		mpz_powm(mpzETrigraphs[i], mpzTrigraphs[i], mpzE, mpzN);
		//For testing encrypted trigraph generation: not passed.  Numbers too large and result in overflow.  Must be fixed with large number handler.
	}
	//Convert enciphered trigraph code into quadragraphs
	int encryptStringCount = 4 * (trigraphCount);
	char encryptString[encryptStringCount];
	mpz_t mpzQuadragraphList[4];
	mpz_init(mpzQuadragraphList[0]);
	mpz_init(mpzQuadragraphList[1]);
	mpz_init(mpzQuadragraphList[2]);
	mpz_init(mpzQuadragraphList[3]);

	for (int i = 0; i < (trigraphCount); i++)
	{
		//Represent enciphered message as a 4-digit base-26 number and converting to alphabetic characters
		
		mpz_t mpzFirstQuotient;
		mpz_t mpzFirstRemainder;
		mpz_init(mpzFirstQuotient);
		mpz_init(mpzFirstRemainder);
		
		mpz_tdiv_qr_ui(mpzFirstQuotient, mpzFirstRemainder, mpzETrigraphs[i], 26 * 26 * 26);
		
		
		mpz_t mpzSecondQuotient;
		mpz_t mpzSecondRemainder;
		mpz_init(mpzSecondQuotient);
		mpz_init(mpzSecondRemainder);
		
		mpz_tdiv_qr_ui(mpzSecondQuotient, mpzSecondRemainder, mpzFirstRemainder, 26 * 26);
		
		mpz_t mpzThirdQuotient;
		mpz_t mpzThirdRemainder;
		mpz_init(mpzThirdQuotient);
		mpz_init(mpzThirdRemainder);
		
		mpz_tdiv_qr_ui(mpzThirdQuotient, mpzThirdRemainder, mpzSecondRemainder, 26);
		
		mpz_mod_ui(mpzQuadragraphList[0], mpzFirstQuotient, 26);
		mpz_mod_ui(mpzQuadragraphList[1], mpzSecondQuotient, 26);
		mpz_mod_ui(mpzQuadragraphList[2], mpzThirdQuotient, 26);
		mpz_mod_ui(mpzQuadragraphList[3], mpzThirdRemainder, 26);
		
		mpz_t mpzQuadEntry;
		mpz_init(mpzQuadEntry);
		
		for (int j = (i * 4); j < (4 + (4 * i)); j++)
		{
			mpz_set(mpzQuadEntry, mpzQuadragraphList[j - (4 * i)]);
			
			if (mpz_cmp_ui(mpzQuadEntry, 0) == 0)
			{
				encryptString[j] = 'A';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 1) == 0)
			{
				encryptString[j] = 'B';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 2) == 0)
			{
				encryptString[j] = 'C';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 3) == 0)
			{
				encryptString[j] = 'D';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 4) == 0)
			{
				encryptString[j] = 'E';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 5) == 0)
			{
				encryptString[j] = 'F';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 6) == 0)
			{
				encryptString[j] = 'G';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 7) == 0)
			{
				encryptString[j] = 'H';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 8) == 0)
			{
				encryptString[j] = 'I';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 9) == 0)
			{
				encryptString[j] = 'J';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 10) == 0)
			{
				encryptString[j] = 'K';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 11) == 0)
			{
				encryptString[j] = 'L';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 12) == 0)
			{
				encryptString[j] = 'M';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 13) == 0)
			{
				encryptString[j] = 'N';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 14) == 0)
			{
				encryptString[j] = 'O';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 15) == 0)
			{
				encryptString[j] = 'P';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 16) == 0)
			{
				encryptString[j] = 'Q';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 17) == 0)
			{
				encryptString[j] = 'R';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 18) == 0)
			{
				encryptString[j] = 'S';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 19) == 0)
			{
				encryptString[j] = 'T';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 20) == 0)
			{
				encryptString[j] = 'U';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 21) == 0)
			{
				encryptString[j] = 'V';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 22) == 0)
			{
				encryptString[j] = 'W';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 23) == 0)
			{
				encryptString[j] = 'X';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 24) == 0)
			{
				encryptString[j] = 'Y';
			}
			else if (mpz_cmp_ui(mpzQuadEntry, 25) == 0)
			{
				encryptString[j] = 'Z';
			}
			else{encryptString[j] = ' ';}
		}
	}

	//Print to outfile
	for (int i = 0; i < encryptStringCount; i++)
	{
		outfile << encryptString[i];
	}
	cout << "\nEncryption Successful!" << endl;
}

void decrypt(mpz_t mpzN, mpz_t mpzD, int numberConversion[], int size, ostream& outfile)
{
	int quadragraphCount = floor(size/4);
	int quadragraphs[quadragraphCount];//Quadragraph array

	//Interpret each quadragraph as a number in base 26
	for (int i = 0; i < quadragraphCount; i++)
	{
		quadragraphs[i] = ( numberConversion[ (i*4) ] * 26 * 26 * 26) + ( numberConversion[ ((i*4)+1) ] * 26 * 26) + ( numberConversion[ ((i*4)+2) ] * 26 ) + numberConversion[ ((i*4)+3) ];
		
	}
	
	mpz_t mpzQuadragraphs[quadragraphCount];
	mpz_t mpzEQuadragraphs[quadragraphCount];
	//Encrypted quadragraph array
	for (int i = 0; i < quadragraphCount; i++)
	{
		mpz_init(mpzQuadragraphs[i]);
		mpz_init(mpzEQuadragraphs[i]);
		
		mpz_set_ui(mpzQuadragraphs[i], quadragraphs[i]);
		
		mpz_powm(mpzEQuadragraphs[i], mpzQuadragraphs[i], mpzD, mpzN); 
	
		//Encipher each ciphertext quadragraph code using M = C^d mod n
		
	}
	
	//Convert enciphered quadragraph code into trigraphs
	int encryptStringCount = 3 * (quadragraphCount);
	char encryptString[encryptStringCount];
	mpz_t mpzTrigraphList[3];
	mpz_init(mpzTrigraphList[0]);
	mpz_init(mpzTrigraphList[1]);
	mpz_init(mpzTrigraphList[2]);
	
	mpz_t mpzFirstQuotient;
	mpz_t mpzFirstRemainder;
	mpz_init(mpzFirstQuotient);
	mpz_init(mpzFirstRemainder);
	
	mpz_t mpzSecondQuotient;
	mpz_t mpzSecondRemainder;
	mpz_init(mpzSecondQuotient);
	mpz_init(mpzSecondRemainder);

	for (int i = 0; i < quadragraphCount; i++)
	{
		
		
		mpz_tdiv_qr_ui(mpzFirstQuotient, mpzFirstRemainder, mpzEQuadragraphs[i], (26 * 26));
		
		mpz_out_str(stdout, 10, mpzFirstQuotient);
		cout << endl;
		
		
		
		mpz_tdiv_qr_ui(mpzSecondQuotient, mpzSecondRemainder, mpzFirstRemainder, 26);
		
		mpz_mod_ui(mpzTrigraphList[0], mpzFirstQuotient, 26);
		mpz_mod_ui(mpzTrigraphList[1], mpzSecondQuotient, 26);
		mpz_mod_ui(mpzTrigraphList[2], mpzSecondRemainder, 26);
		
		//Represent enciphered message as a 3-digit base-26 number and converting to alphabetic characters
		
		mpz_t mpzTriEntry;
		mpz_init(mpzTriEntry);
		
		for (int j = (i*3); j < (3 + (i * 3)); j++)
		{
			mpz_set(mpzTriEntry, mpzTrigraphList[j - (3 * i)]);
			
			
			if (mpz_cmp_ui(mpzTriEntry, 0) == 0)
			{
				encryptString[j] = 'A';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 1) == 0)
			{
				encryptString[j] = 'B';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 2) == 0)
			{
				encryptString[j] = 'C';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 3) == 0)
			{
				encryptString[j] = 'D';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 4) == 0)
			{
				encryptString[j] = 'E';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 5) == 0)
			{
				encryptString[j] = 'F';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 6) == 0)
			{
				encryptString[j] = 'G';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 7) == 0)
			{
				encryptString[j] = 'H';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 8) == 0)
			{
				encryptString[j] = 'I';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 9) == 0)
			{
				encryptString[j] = 'J';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 10) == 0)
			{
				encryptString[j] = 'K';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 11) == 0)
			{
				encryptString[j] = 'L';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 12) == 0)
			{
				encryptString[j] = 'M';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 13) == 0)
			{
				encryptString[j] = 'N';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 14) == 0)
			{
				encryptString[j] = 'O';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 15) == 0)
			{
				encryptString[j] = 'P';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 16) == 0)
			{
				encryptString[j] = 'Q';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 17) == 0)
			{
				encryptString[j] = 'R';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 18) == 0)
			{
				encryptString[j] = 'S';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 19) == 0)
			{
				encryptString[j] = 'T';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 20) == 0)
			{
				encryptString[j] = 'U';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 21) == 0)
			{
				encryptString[j] = 'V';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 22) == 0)
			{
				encryptString[j] = 'W';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 23) == 0)
			{
				encryptString[j] = 'X';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 24) == 0)
			{
				encryptString[j] = 'Y';
			}
			else if (mpz_cmp_ui(mpzTriEntry, 25) == 0)
			{
				encryptString[j] = 'Z';
			}
			else{encryptString[j] = ' ';}
		}
	}

	//Print to outfile
	for (int i = 0; i < encryptStringCount; i++)
	{
		outfile << encryptString[i];
	}
	cout << "\nDecryption Successful!" << endl;
	
}

int main ()
{
	ifstream in_file;
	ofstream out_file;

	string input_file_name, output_file_name;
	char x;

	const int maxStringLength = 40;
	char textString[maxStringLength];
	int num, k, p, q, totient, n, e, d;
	
	bool done = false;

	srand (time(NULL));
	//Pseudo-random number generator seeded with current time

	cout << "Please enter the name of your output file:  ";
	cin >> output_file_name;
	out_file.open(output_file_name.c_str());
	if ( !out_file)
	{
		cout << "Could not open output file \n";
		return 0;
	}

	cout << "Please enter the name of your input file:  ";
	cin >> input_file_name;
	in_file.open(input_file_name.c_str());
	if( !in_file)
	{
		cout << "Error.  Please check your syntax and try again. \n";
		return 0;
	}

	int count = 0;
	in_file >> textString[count];
	count++;

	//Read input file to character array
	while ( (count < maxStringLength) && (in_file >> textString[count]) )
	{
		count++;
	}

	int numberConversion[count];

	//Convert character array to integer array
	for(int i = 0; i < count; i++)
	{
		if ( (textString[i] == 'A') || (textString[i] == 'a') )
		{
			numberConversion[i] = 0;
		}
		else if ( (textString[i] == 'B') || (textString[i] == 'b') )
		{
			numberConversion[i] = 1;
		}
		else if ( (textString[i] == 'C') || (textString[i] == 'c') )
		{
			numberConversion[i] = 2;
		}
		else if ( (textString[i] == 'D') || (textString[i] == 'd') )
		{
			numberConversion[i] = 3;
		}
		else if ( (textString[i] == 'E') || (textString[i] == 'e') )
		{
			numberConversion[i] = 4;
		}
		else if ( (textString[i] == 'F') || (textString[i] == 'f') )
		{
			numberConversion[i] = 5;
		}
		else if ( (textString[i] == 'G') || (textString[i] == 'g') )
		{
			numberConversion[i] = 6;
		}
		else if ( (textString[i] == 'H') || (textString[i] == 'h') )
		{
			numberConversion[i] = 7;
		}
		else if ( (textString[i] == 'I') || (textString[i] == 'i') )
		{
			numberConversion[i] = 8;
		}
		else if ( (textString[i] == 'J') || (textString[i] == 'j') )
		{
			numberConversion[i] = 9;
		}
		else if ( (textString[i] == 'K') || (textString[i] == 'k') )
		{
			numberConversion[i] = 10;
		}
		else if ( (textString[i] == 'L') || (textString[i] == 'l') )
		{
			numberConversion[i] = 11;
		}
		else if ( (textString[i] == 'M') || (textString[i] == 'm') )
		{
			numberConversion[i] = 12;
		}
		else if ( (textString[i] == 'N') || (textString[i] == 'n') )
		{
			numberConversion[i] = 13;
		}
		else if ( (textString[i] == 'O') || (textString[i] == 'o') )
		{
			numberConversion[i] = 14;
		}
		else if ( (textString[i] == 'P') || (textString[i] == 'p') )
		{
			numberConversion[i] = 15;
		}
		else if ( (textString[i] == 'Q') || (textString[i] == 'q') )
		{
			numberConversion[i] = 16;
		}
		else if ( (textString[i] == 'R') || (textString[i] == 'r') )
		{
			numberConversion[i] = 17;
		}
		else if ( (textString[i] == 'S') || (textString[i] == 's') )
		{
			numberConversion[i] = 18;
		}
		else if ( (textString[i] == 'T') || (textString[i] == 't') )
		{
			numberConversion[i] = 19;
		}
		else if ( (textString[i] == 'U') || (textString[i] == 'u') )
		{
			numberConversion[i] = 20;
		}
		else if ( (textString[i] == 'V') || (textString[i] == 'v') )
		{
			numberConversion[i] = 21;
		}
		else if ( (textString[i] == 'W') || (textString[i] == 'w') )
		{
			numberConversion[i] = 22;
		}
		else if ( (textString[i] == 'X') || (textString[i] == 'x') )
		{
			numberConversion[i] = 23;
		}
		else if ( (textString[i] == 'Y') || (textString[i] == 'Y') )
		{
			numberConversion[i] = 24;
		}
		else if ( (textString[i] == 'Z') || (textString[i] == 'z') )
		{
			numberConversion[i] = 25;
		}
		else {}
	}
	

	int choice;
	cout << "Do you wish to encrypt or decrypt?  Type 1 for ENCRYPT and type 2 for DECRYPT." << endl;
	cin >> choice;
	if (choice == 1)
	//ENCRYPT
	{

		//Calculate p
		mpz_t l, mpzConvertP;
		unsigned long seed;
		seed = time(NULL);
		// perform inits to create variable pointers with 0 values
		mpz_init(mpzConvertP);
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
			mpz_urandomb(mpzConvertP, rstate, 340);
			// add base to generated number, should now be between 10^100 and 2*10^100
			mpz_add(mpzConvertP, mpzConvertP, l);
		
		} while ((mpz_probab_prime_p(mpzConvertP, 25)) == 0);

		//Calculate q
		mpz_t m, mpzConvertQ;
		//unsigned long seed;
		seed = rand();
		// perform inits to create variable pointers with 0 values
		mpz_init(mpzConvertQ);
		mpz_init(m);
		
		// calculate random number floor (at least 100 digits long)
		mpz_ui_pow_ui(m, 10, 100);
		// initialize the random number seed
		//gmp_randstate_t rstate;
		// initialize state for a Mersenne Twister algorithm
		gmp_randinit_mt(rstate);
		// create the generatero seed for random number engine
		gmp_randseed_ui(rstate, seed);
		
		do {
			// generate number between 0 and 2^340 (~10^103 in base 2)
			mpz_urandomb(mpzConvertQ, rstate, 340);
			// add base to generated number, should now be between 10^100 and 2*10^100
			mpz_add(mpzConvertQ, mpzConvertQ, m);
		
		} while ((mpz_probab_prime_p(mpzConvertQ, 25)) == 0);

		mpz_t mpzN;
		mpz_t mpzTotient;
		mpz_t mpzPMinus;
		mpz_t mpzQMinus;
		mpz_init(mpzN);
		mpz_init(mpzTotient);
		mpz_init(mpzPMinus);
		mpz_init(mpzQMinus);
		
		mpz_mul(mpzN, mpzConvertP, mpzConvertQ);
		
		mpz_sub_ui(mpzPMinus, mpzConvertP, 1);
		mpz_sub_ui(mpzQMinus, mpzConvertQ, 1);
		
		mpz_mul(mpzTotient, mpzPMinus, mpzQMinus);

		
		mpz_t mpzE;
		mpz_init(mpzE);
		
		mpz_set_ui(mpzE, 65537);
		

		
		mpz_t mpzD;
		mpz_init(mpzD);
 
		mpz_t mpzCalcMod;
		mpz_t mpzMulED;
		
		mpz_init(mpzCalcMod);
		mpz_init(mpzMulED);

/*THE FOLLOWING MANUAL ASSIGNMENTS FOR P, Q, N, TOTIENT, AND E CAN BE UNCOMMENTED TO VERIFY WORKING ENCRYPT/DECRYPT ALGORITHMS*/

		///*
		mpz_set_ui(mpzConvertP, 167);
		mpz_set_ui(mpzConvertQ, 307);
		mpz_set_ui(mpzN, 51269);
		mpz_set_ui(mpzTotient, 50796);
		mpz_set_ui(mpzE, 5);
		//*/

		mpz_invert(mpzD, mpzE, mpzTotient);

		//Print p, q, e, and d
		cout << "p = ";
		mpz_out_str(stdout,10,mpzConvertP);
		cout << endl;

		cout << "q = ";
		mpz_out_str(stdout,10,mpzConvertQ);
		cout << endl;

		cout << "e = ";
		mpz_out_str(stdout, 10, mpzE);
		cout << endl;

		cout << "d = ";
		mpz_out_str(stdout, 10, mpzD);
		cout << endl;

		encrypt(mpzConvertP, mpzConvertQ, mpzE, numberConversion, 30, out_file);

		cout << "For decryption:  " << endl;
		cout << "n = ";
		mpz_out_str(stdout, 10, mpzN);
		cout << endl;
		cout << "d = ";
		mpz_out_str(stdout, 10, mpzD);
		cout << endl;

		out_file.close();
		
	}
	else if (choice == 2)
	//DECRYPT
	{
		mpz_t mpzDecryptN;
		mpz_t mpzDecryptD;
		mpz_init(mpzDecryptN);
		mpz_init(mpzDecryptD);
		cout << "Enter modulus value (n) and private key (d) separated by a space " ":  ";
		mpz_inp_str(mpzDecryptN, stdin, 10);
		mpz_inp_str(mpzDecryptD, stdin, 10);
		
		mpz_out_str(stdout, 10, mpzDecryptN);
		cout << endl;
		
		mpz_out_str(stdout, 10, mpzDecryptD);
		cout << endl;
		
		decrypt(mpzDecryptN, mpzDecryptD, numberConversion, 40, out_file);
		out_file.close();
		string line;
		ifstream file("second.txt");
		if (file.is_open())
		{
			while (getline(file, line))
			{
				cout << line << endl;
			}
			file.close();
		}
	}
	else
	//ERROR
	{
		cout << "ERROR.  Invalid choice." << endl;
	}
	return 0;
	
}


