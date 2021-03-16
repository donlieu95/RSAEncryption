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
//Don Lieu
//Description: Simulate RSA Encryption

using namespace std;
//For random selection of p and q
const int max_num = 1000000, min_num = 100;

bool isPrime(int n, int k)
//Test for primality using Miller-Rabin method.  Make less ugly later.
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

void encrypt(int p, int q, int e, int d, int numberConversion[], int size)
{
	int trigraphCount = floor(size/3), remainder = size % 3, n = p*q, totient = (p-1)*(q-1);
	int trigraphs[trigraphCount+1];

	for (int i = 0; i < trigraphCount; i++)
	{
		trigraphs[i] = ( numberConversion[ (i*3) ] * 26 * 26 ) + ( numberConversion[ ((i*3)+1) ] * 26 ) + numberConversion[ ((i*3)+2) ];
	}

	if (remainder == 2)
	{
		trigraphs[trigraphCount+1] = ( numberConversion[ ( (trigraphCount+1) *3) ] * 26 ) + numberConversion[ ( ( (trigraphCount+1) *3)+1) ];
	}
	else if (remainder == 1)
	{
		trigraphs[trigraphCount+1] = numberConversion[ ( (trigraphCount+1) *3) ];
	}
	else{}

	int eTrigraphs[trigraphCount+1];
	for (int i = 0; i < trigraphCount+1; i++)
	{
		eTrigraphs[i] = (int)(pow(trigraphs[i], e) + 0.5) % n;
	}
	cout << "Conversion successful up to c = M^e mod n" << endl;
}

void decrypt()
{
}

int main ()
{
	ifstream in_file;
	ofstream out_file;

	string input_file_name, output_file_name;
	char x;

	const int maxStringLength = 30;
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

	while ( (count < maxStringLength) && (in_file >> textString[count]) )
	{
		count++;
	}

	int numberConversion[count];

	for(int i = 0; i < count; i++)
	{
		if ( (textString[i] == 'A') || (textString[i] == 'a') )
		{
			numberConversion[i] = 1;
		}
		else if ( (textString[i] == 'B') || (textString[i] == 'b') )
		{
			numberConversion[i] = 2;
		}
		else if ( (textString[i] == 'C') || (textString[i] == 'c') )
		{
			numberConversion[i] = 3;
		}
		else if ( (textString[i] == 'D') || (textString[i] == 'd') )
		{
			numberConversion[i] = 4;
		}
		else if ( (textString[i] == 'E') || (textString[i] == 'e') )
		{
			numberConversion[i] = 5;
		}
		else if ( (textString[i] == 'F') || (textString[i] == 'f') )
		{
			numberConversion[i] = 6;
		}
		else if ( (textString[i] == 'G') || (textString[i] == 'g') )
		{
			numberConversion[i] = 7;
		}
		else if ( (textString[i] == 'H') || (textString[i] == 'h') )
		{
			numberConversion[i] = 8;
		}
		else if ( (textString[i] == 'I') || (textString[i] == 'i') )
		{
			numberConversion[i] = 9;
		}
		else if ( (textString[i] == 'J') || (textString[i] == 'j') )
		{
			numberConversion[i] = 10;
		}
		else if ( (textString[i] == 'K') || (textString[i] == 'k') )
		{
			numberConversion[i] = 11;
		}
		else if ( (textString[i] == 'L') || (textString[i] == 'l') )
		{
			numberConversion[i] = 12;
		}
		else if ( (textString[i] == 'M') || (textString[i] == 'm') )
		{
			numberConversion[i] = 13;
		}
		else if ( (textString[i] == 'N') || (textString[i] == 'n') )
		{
			numberConversion[i] = 14;
		}
		else if ( (textString[i] == 'O') || (textString[i] == 'o') )
		{
			numberConversion[i] = 15;
		}
		else if ( (textString[i] == 'P') || (textString[i] == 'p') )
		{
			numberConversion[i] = 16;
		}
		else if ( (textString[i] == 'Q') || (textString[i] == 'q') )
		{
			numberConversion[i] = 17;
		}
		else if ( (textString[i] == 'R') || (textString[i] == 'r') )
		{
			numberConversion[i] = 18;
		}
		else if ( (textString[i] == 'S') || (textString[i] == 's') )
		{
			numberConversion[i] = 19;
		}
		else if ( (textString[i] == 'T') || (textString[i] == 't') )
		{
			numberConversion[i] = 20;
		}
		else if ( (textString[i] == 'U') || (textString[i] == 'u') )
		{
			numberConversion[i] = 21;
		}
		else if ( (textString[i] == 'V') || (textString[i] == 'v') )
		{
			numberConversion[i] = 22;
		}
		else if ( (textString[i] == 'W') || (textString[i] == 'w') )
		{
			numberConversion[i] = 23;
		}
		else if ( (textString[i] == 'X') || (textString[i] == 'x') )
		{
			numberConversion[i] = 24;
		}
		else if ( (textString[i] == 'Y') || (textString[i] == 'Y') )
		{
			numberConversion[i] = 25;
		}
		else if ( (textString[i] == 'Z') || (textString[i] == 'z') )
		{
			numberConversion[i] = 26;
		}
		else {}
	}

	

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

	int choice;
	cout << "Do you wish to encrypt or decrypt?  Type 1 for ENCRYPT and type 2 for DECRYPT." << endl;
	cin >> choice;
	if (choice == 1)
	{
		encrypt(p, q, e, d, numberConversion, count);
	}
	else if (choice == 2)
	{
		//Decrypt
	}
	else
	{
		cout << "ERROR.  Invalid choice." << endl;
	}
	return 0;
	
}
