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

void print_message(char * msg){
    printf("%s", msg);
}

int main(){
    int input = 0;
    scanf("%d", &input);
    switch(input){
        case 3:
            print_message("[Case 3]: Hello\n");
            break;
        case 20:
            printf("[Case 20]: Bello\n");
            break;
        case 79:
            puts("[Case 79]: Cello");
            break;
        case 29:
            puts("[Case 29]: Cello");
            break;
        case 12:
            puts("[Case 12]: Cello");
            break;
        case 99:
            puts("[Case 99]: Cello");
            break;
        case 33:
            puts("[Case 33]: Cello");
            break;
        case 41:
            puts("[Case 41]: Cello");
            break;
        default:
            print_message("[Default]: Dello\n");
            break;
    }
    return 0;
}
