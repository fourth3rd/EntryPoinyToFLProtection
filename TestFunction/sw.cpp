#define _CRT_SECURE_NO_WARNINGS

#include<stdio.h>
#include<string>
#include<Windows.h>

void PrintTest();

void PrintHello()
{
	MessageBoxEx(NULL, L"Print Hello", 0, 0, 0);
}

int main()
{
	int A;
	int B;

	scanf("%d %d", &A, &B);

	int Sum = A + B;
	printf("%d\n", Sum);
	MessageBoxEx(NULL, L"Entry Test", 0, 0, 0);
	PrintHello();
	PrintTest();
}

void PrintTest()
{
	MessageBoxEx(NULL, L"Print Test", 0, 0, 0);
}