/*
    This file is part of AFL-Cast.

    AFL-Cast is free software: you can redistribute it and/or modify it under the terms of the 
    GNU General Public License as published by the Free Software Foundation, either version 3 
    of the License, or (at your option) any later version.

    AFL-Cast is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with AFL-Cast. 
    If not, see <https://www.gnu.org/licenses/>. 

*/
#include <stdio.h>
#include <sys/cdefs.h>


int __attribute__ ((noinline)) get_mul(char * data, int num){
    int mul = 0;
    for (int i = 0; i < 0x1000; i++){
        mul *= data[i] ^ num;
    }
    return mul * num;
}

int __attribute__ ((noinline)) get_sum(char * data, int num){
    int sum = 0;
    for (int i = 0; i < 0x1000; i++){
        sum += data[i] ^ num;
    }

    return sum + num;
}

int __attribute__ ((noinline)) parse(char * data){
    int as = 0;
    int bs = 0;
    for (int i = 0; i < 0x1000; i++){
        if (data[i] == 'A'){
            as++;
            as += get_sum(data, as);
        }

        if (data[i] == 'B'){
            bs++;
            bs += get_mul(data, bs);
        }
    }

    return as + bs;
}

int main(){
    char data[0x10000] = {0};
    scanf("%4096s", data);
    printf("num: %d", parse(data));
}
