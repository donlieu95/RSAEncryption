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
const int max_num = 1000000, min_num = 100;

bool isPrime(int n, int k)
//Test for primality using Miller-Rabin method.  Make variable names sensible later.
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
int main ()
{
	int num, k, p, q, totient, n, e, d;
	bool done = false;
	srand (time(NULL));
	//Pseudo-random number generator seeded with current time

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


	
	return 0;
	
}
