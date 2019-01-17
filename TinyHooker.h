/*
	Copyright 2019 Ognyan Mirev
	Permission is hereby granted, free of charge, to any person
	obtaining a copy of this software and associated documentation
	files (the "Software"), to deal in the Software without restriction,
	including without limitation the rights to use, copy, modify, merge,
	publish, distribute, sublicense, and/or sell copies of the Software,
	and to permit persons to whom the Software is furnished to do so,
	subject to the following conditions:
	The above copyright notice and this permission notice shall be included
	in all copies or substantial portions of the Software.
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
	OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
	WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
	CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once
#include <Windows.h>
typedef unsigned long uint32_t;

#define WORD_SIZE 4
#define arch_int uint32_t
#define PLACEHOLDER 0xffffffff

#define PROLOGUE_SIZE WORD_SIZE + 1
#define TEMPLATE_SIZE 11

#define uintxx_t arch_int


/*
	pFn is a pointer to the target function
	pHook is a pointer to the detour function
	MetaData is an optional argument which will be passed to the detour

	returns FunctionSpecificShellcode, the memory which will be called every time pFn is called
*/
byte* HookFn(PBYTE pFn, PBYTE pHook, PVOID MetaData)
{
	const byte Template[] =
	{
		0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax, 0xffffffff ; Pointer to metadata
		0x50,                         // push eax
		0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax, 0xffffffff ; Hook offset
	};


	uintxx_t *CallAddress, *HookRelative, dwTotalShellcodeSize = PROLOGUE_SIZE + sizeof(Template) + 5, *JmpRelative;

	DWORD OldProtect;

	VirtualProtect(pFn, WORD_SIZE + 1, PAGE_EXECUTE_READWRITE, &OldProtect); // Make the start of the target function writeable

	byte* FunctionSpecificShellcode = (byte*)malloc(dwTotalShellcodeSize); // Allocate a buffer for the function used to intercept the target

	VirtualProtect(FunctionSpecificShellcode, dwTotalShellcodeSize, PAGE_EXECUTE_READWRITE, &OldProtect);

	memcpy(FunctionSpecificShellcode, Template, TEMPLATE_SIZE);
	memcpy(FunctionSpecificShellcode + TEMPLATE_SIZE, pFn, PROLOGUE_SIZE);

	PVOID* FnIndexPtr = (PVOID*)(FunctionSpecificShellcode + 1);
	*FnIndexPtr = MetaData;

	FunctionSpecificShellcode[6] = 0xe8; // Call after push
	HookRelative = (uintxx_t*)(FunctionSpecificShellcode + 7); // Call address
	*HookRelative = (uintxx_t)(pHook - (byte*)HookRelative - 4); // Set Call address


	JmpRelative = (uintxx_t*)(FunctionSpecificShellcode + sizeof(Template) + PROLOGUE_SIZE);
	*((byte*)JmpRelative) = 0xe9;
	JmpRelative = (uintxx_t*)((byte*)JmpRelative + 1);
	*JmpRelative = (uintxx_t)((byte*)pFn - (byte*)JmpRelative + 1);


	pFn[0] = 0xe9; // Relative jmp
	CallAddress = (uintxx_t*)(pFn + 1);
	*CallAddress = (uintxx_t)FunctionSpecificShellcode - (DWORD)pFn - 5; // Hook it with the address of FunctionSpecificShellcode

	return FunctionSpecificShellcode;
}

void UnHookFn(PBYTE pFn, PBYTE pFunctionSpecificShellcode)
{
	memcpy(pFn, pFunctionSpecificShellcode + TEMPLATE_SIZE, PROLOGUE_SIZE);
}
