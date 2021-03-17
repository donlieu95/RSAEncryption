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

//CSCI 415, Computer Security
//Project 1
//Group 1
//Don Lieu
//Description: Simulate RSA Encryption
//Note:  Currently, converting text to 3 or 4 digit base-26 numbers result in numbers too large for the program to handle without overflow.  This must be fixed with a large number handler.

using namespace std;
//For random selection of p and q
const int max_num = 100000, min_num = 100;

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

void encrypt(int p, int q, int e, int d, int numberConversion[], int size, ostream& outfile)
{
	int trigraphCount = floor(size/3), n = p*q, totient = (p-1)*(q-1);
	int trigraphs[trigraphCount];//Trigraph array

	//Interpret each trigraph as a number in base 26
	for (int i = 0; i < trigraphCount; i++)
	{
		trigraphs[i] = ( numberConversion[ (i*3) ] * 26 * 26 ) + ( numberConversion[ ((i*3)+1) ] * 26 ) + numberConversion[ ((i*3)+2) ];
		//For testing trigraph generation: passed
		//cout << trigraphs[i] << " ";
	}
	//For testing trigraph generation: passed
	//cout << endl;

	int eTrigraphs[trigraphCount];//Encrypted trigraph array
	for (int i = 0; i < trigraphCount; i++)
	{
		//Encipher each plaintext trigraph code using C = M^e mod n
		eTrigraphs[i] = (int)(pow(trigraphs[i], e) + 0.5) % n;

		//For testing encrypted trigraph generation: not passed.  Numbers too large and result in overflow.  Must be fixed with large number handler.
		cout << eTrigraphs[i];
	}

	//Convert enciphered trigraph code into quadragraphs
	int encryptStringCount = 4 * (trigraphCount);
	char encryptString[encryptStringCount];
	int quadragraphList[4];

	for (int i = 0; i < (trigraphCount); i++)
	{
		//Represent enciphered message as a 4-digit base-26 number and converting to alphabetic characters
		int firstQuotient = eTrigraphs[i] / ((int)(pow(26,3) + 0.5));
		int firstRemainder = eTrigraphs[i] % ((int)(pow(26,3) + 0.5));

		int secondQuotient = firstRemainder / ((int)(pow(26,2) + 0.5));
		int secondRemainder = firstRemainder / ((int)(pow(26,2) + 0.5));

		int thirdQuotient = secondRemainder / 26;
		int thirdRemainder = secondRemainder % 26;
	
		quadragraphList[0] = firstQuotient;
		quadragraphList[1] = secondQuotient;
		quadragraphList[2] = thirdQuotient;
		quadragraphList[3] = thirdRemainder;
		
		int count = 0;

		for (int j = (i*4); j < encryptStringCount; j++)
		{
			int quadEntry = quadragraphList[count];
			
			if (quadEntry == 0)
			{
				encryptString[j] = 'A';
			}
			else if (quadEntry == 1)
			{
				encryptString[j] = 'B';
			}
			else if (quadEntry == 2)
			{
				encryptString[j] = 'C';
			}
			else if (quadEntry == 3)
			{
				encryptString[j] = 'D';
			}
			else if (quadEntry == 4)
			{
				encryptString[j] = 'E';
			}
			else if (quadEntry == 5)
			{
				encryptString[j] = 'F';
			}
			else if (quadEntry == 6)
			{
				encryptString[j] = 'G';
			}
			else if (quadEntry == 7)
			{
				encryptString[j] = 'H';
			}
			else if (quadEntry == 8)
			{
				encryptString[j] = 'I';
			}
			else if (quadEntry == 9)
			{
				encryptString[j] = 'J';
			}
			else if (quadEntry == 10)
			{
				encryptString[j] = 'K';
			}
			else if (quadEntry == 11)
			{
				encryptString[j] = 'L';
			}
			else if (quadEntry == 12)
			{
				encryptString[j] = 'M';
			}
			else if (quadEntry == 13)
			{
				encryptString[j] = 'N';
			}
			else if (quadEntry == 14)
			{
				encryptString[j] = 'O';
			}
			else if (quadEntry == 15)
			{
				encryptString[j] = 'P';
			}
			else if (quadEntry == 16)
			{
				encryptString[j] = 'Q';
			}
			else if (quadEntry == 17)
			{
				encryptString[j] = 'R';
			}
			else if (quadEntry == 18)
			{
				encryptString[j] = 'S';
			}
			else if (quadEntry == 19)
			{
				encryptString[j] = 'T';
			}
			else if (quadEntry == 20)
			{
				encryptString[j] = 'U';
			}
			else if (quadEntry == 21)
			{
				encryptString[j] = 'V';
			}
			else if (quadEntry == 22)
			{
				encryptString[j] = 'W';
			}
			else if (quadEntry == 23)
			{
				encryptString[j] = 'X';
			}
			else if (quadEntry == 24)
			{
				encryptString[j] = 'Y';
			}
			else if (quadEntry == 25)
			{
				encryptString[j] = 'Z';
			}
			else{encryptString[j] = ' ';}
			count++;
		}
	}

	//Print to outfile
	for (int i = 0; i < encryptStringCount; i++)
	{
		outfile << encryptString[i];
	}
	cout << "\nEncryption Successful!" << endl;
}

void decrypt(int n, int d, int numberConversion[], int size, ostream& outfile)
{
	int quadragraphCount = floor(size/4);
	int quadragraphs[quadragraphCount];//Quadragraph array

	//Interpret each quadragraph as a number in base 26
	for (int i = 0; i < quadragraphCount; i++)
	{
		quadragraphs[i] = ( numberConversion[ (i*3) ] * 26 * 26 * 26) + ( numberConversion[ ((i*3)+1) ] * 26 * 26) + ( numberConversion[ ((i*3)+2) ] * 26 ) + numberConversion[ ((i*3)+3) ];
		//Test for quadragraph generation: passed
		//cout << quadragraphs[i] << " ";
	}
	//Test for quadragraph generation: passed
	//cout << endl;

	int eQuadragraphs[quadragraphCount];//Encrypted quadragraph array
	for (int i = 0; i < quadragraphCount; i++)
	{
		//Encipher each ciphertext quadragraph code using M = C^d mod n
		eQuadragraphs[i] = ( (int)(pow(quadragraphs[i], d) + 0.5) % n);
		//Test for quadragraph encryption: not passed.  Need properly encrypted RSA outfile for testing.
		cout << eQuadragraphs[i];
	}
	
	//Convert enciphered quadragraph code into trigraphs
	int encryptStringCount = 3 * (quadragraphCount);
	char encryptString[encryptStringCount];
	int trigraphList[3];

	for (int i = 0; i < (quadragraphCount); i++)
	{
		//Represent enciphered message as a 3-digit base-26 number and converting to alphabetic characters
		int firstQuotient = eQuadragraphs[i] / ((int)(pow(26,2) + 0.5));
		int firstRemainder = eQuadragraphs[i] % ((int)(pow(26,2) + 0.5));

		int secondQuotient = firstRemainder / 26;
		int secondRemainder = firstRemainder % 26;
	
		trigraphList[0] = firstQuotient;
		trigraphList[1] = secondQuotient;
		trigraphList[2] = secondRemainder;
		
		int count = 0;

		for (int j = (i*3); j < encryptStringCount; j++)
		{
			int triEntry = trigraphList[count];
			
			if (triEntry == 0)
			{
				encryptString[j] = 'A';
			}
			else if (triEntry == 1)
			{
				encryptString[j] = 'B';
			}
			else if (triEntry == 2)
			{
				encryptString[j] = 'C';
			}
			else if (triEntry == 3)
			{
				encryptString[j] = 'D';
			}
			else if (triEntry == 4)
			{
				encryptString[j] = 'E';
			}
			else if (triEntry == 5)
			{
				encryptString[j] = 'F';
			}
			else if (triEntry == 6)
			{
				encryptString[j] = 'G';
			}
			else if (triEntry == 7)
			{
				encryptString[j] = 'H';
			}
			else if (triEntry == 8)
			{
				encryptString[j] = 'I';
			}
			else if (triEntry == 9)
			{
				encryptString[j] = 'J';
			}
			else if (triEntry == 10)
			{
				encryptString[j] = 'K';
			}
			else if (triEntry == 11)
			{
				encryptString[j] = 'L';
			}
			else if (triEntry == 12)
			{
				encryptString[j] = 'M';
			}
			else if (triEntry == 13)
			{
				encryptString[j] = 'N';
			}
			else if (triEntry == 14)
			{
				encryptString[j] = 'O';
			}
			else if (triEntry == 15)
			{
				encryptString[j] = 'P';
			}
			else if (triEntry == 16)
			{
				encryptString[j] = 'Q';
			}
			else if (triEntry == 17)
			{
				encryptString[j] = 'R';
			}
			else if (triEntry == 18)
			{
				encryptString[j] = 'S';
			}
			else if (triEntry == 19)
			{
				encryptString[j] = 'T';
			}
			else if (triEntry == 20)
			{
				encryptString[j] = 'U';
			}
			else if (triEntry == 21)
			{
				encryptString[j] = 'V';
			}
			else if (triEntry == 22)
			{
				encryptString[j] = 'W';
			}
			else if (triEntry == 23)
			{
				encryptString[j] = 'X';
			}
			else if (triEntry == 24)
			{
				encryptString[j] = 'Y';
			}
			else if (triEntry == 25)
			{
				encryptString[j] = 'Z';
			}
			else{encryptString[j] = ' ';}
			count++;
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
		//Testing alpha to integer passed
		//cout << numberConversion[i] << " ";
	}
	

	int choice;
	cout << "Do you wish to encrypt or decrypt?  Type 1 for ENCRYPT and type 2 for DECRYPT." << endl;
	cin >> choice;
	if (choice == 1)
	//ENCRYPT
	{
		cout << "How many times do you wish to run the Miller test? (Larger number will be more accurate, but will take longer.  For best results, select a number between 2 and 10.)" << endl;
		cin >> k;
		
		while(!done)
		{
			num = rand() % max_num + min_num;
			if (isPrime(num, k) == true)
			{
				p = num;
				cout << "p=" << p << endl;
				done = true;
			}
		}
		//Find q value
		done = false;
		while(!done)
		{
			num = rand() % max_num + min_num;
			if (isPrime(num, k) == true)
			{
				q = num;
				cout << "q=" << q << endl;
				done = true;
			}
		}
		//Get d and e values
		n = p*q;
		totient = (p-1)*(q-1);

		e = 2;
		while ( ( (__gcd(e, totient) != 1) ) )
		{
			e++;
		}
		cout << "e=" << e << endl;

		d = floor(totient/e);
		while ( ( (e*d) % totient) != 1)
		{
			d++;
		}
		cout << "d=" << d << endl;
		encrypt(p, q, e, d, numberConversion, 30, out_file);
	}
	else if (choice == 2)
	//DECRYPT
	{
		cout << "Enter modulus value (n) and private key (d) separated by a space " ":  ";
		cin >> n;
		cin >> d;
		decrypt(n, d, numberConversion, 40, out_file);
	}
	else
	//ERROR
	{
		cout << "ERROR.  Invalid choice." << endl;
	}
	return 0;
	
}
