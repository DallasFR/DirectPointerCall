# DirectPointerCall

With DPC (DirectPointerCall) you take a dyanmicly pointer on targeted function. Function called is not present on IAT tables and no strings was present.

How it's work ?

1) Search the address of API
2) Parse the EAT of API to find address of targeted function
3) Return pointer of targeted function
4) Execute function

#For reverser

You need to make a program to parse all API/Fonction with hashing algorythm to find match with hash in program.
![alt text](https://raw.githubusercontent.com/DallasFR/DirectPointerCall/main/images/ida_screen.PNG)
![alt text](https://raw.githubusercontent.com/DallasFR/DirectPointerCall/main/images/prog_screen.PNG)
