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
	MessageBoxEx(NULL, L"Entry Test", 0, 0, 0);
}

void PrintTest()
{
	MessageBoxEx(NULL, L"Print Test", 0, 0, 0);
}