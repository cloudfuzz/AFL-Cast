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

int get_zero(int arg){
    return (arg * (arg + 1) * (arg + 2)) % 6;
}

int get_fool(){
    if (1){
        return 2;
    }
    else {
        return 3;
    }
}

int get_bool(){
    if (2){
        return 4;
    }
    else {
        return 5;
    }
}


int main(){
    int zero1 = 0;
    int zero2 = 0;
    if (get_zero(1) == 0){
       zero1 = get_bool();
    }
    else {
        zero2 = get_fool();
    }

    return zero1 + zero2;
}
