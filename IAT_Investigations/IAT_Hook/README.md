Goal

This is a little POC to demonstrating overwriting a processes own IAT table entry with an arbitrary function. 
The Import Address Table (IAT), is a table that every prcess has that maps a function name with its address (there are two structures - one for the name and another for address- 
and is why our code has two iterators ```originalFirstThunk``` and ```firstThunk```).

In this demo, we find the IAT entry for ```MessageBoxA``` and we overwrite it with ```hookedMessageBox```. The behavior of this code may seem unspecial if you don't realize what's happening.
Running this program will pop up 3 windows (one after another), with three texts and headers. 

What's going on under the hood? See ```localHook()``` function.

1) The first window is a standard ```MessageBoxA```. Called by ```MessageBoxA(NULL, "Before hook", "Before hook caption", 0);```
2) Then we search through the IAT until we find the entry for ```MessageBoxA```
3) We then overwrite the function address of ```MessageBoxA``` from the original function to our specially made ```hookedMessageBox``` function.
4) Our custom ```hookedMessageBox``` then calls ```MessageBoxW(NULL, L"NEW HOOKed Message Box", L"NEW HOOKed Message Caption", 0)``` (this is the Wide String version).
   It also returns ```originalMsgBox(hWnd, lpText, lpCaption, uType)``` which is the orignal ANSI version of the function we overwrote the IAT entry for.
5) Finally we call ```MessageBoxA(NULL, "After hook", "After hook caption", 0);```.

So the first window is the original ```MessageBoxA``` function. The second and third windows are from our custom function (the first being the Wide version and the second being the original ANSI function).

In the future, we can try overwritting a remote process's IAT (given that we have permissions to Open and Write to its memory).

Build

```cl localIATHook.c```
