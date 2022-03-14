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
        case 1:
            print_message("[Case 1]: Hello\n");
            break;
        case 2:
            printf("[Case 2]: Bello\n");
            break;
        case 3:
            puts("[Case 3]: Cello");
            break;
        default:
            print_message("[Default]: Dello\n");
            break;
    }
    return 0;
}
