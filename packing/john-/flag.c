//Second part of flag, middle

#include <math.h>	
#include <stdio.h>

int main(int argc, char const *argv[]){

	__int64_t chars[] = {0x1ca66fe7dd, 0x227357afcf8, 0x15, 0x16c5c156c54, 0x1ca66fe7dd, 0x9de93ece66, 
	0x16c5c156c54, 0x16c5c156c54, 0x756f3444241, 0x14660a4c5, 0x1ca66fe7dd};

	for(int j=0; j<11; j++){
		for(int i=0x20; i< 0x7f; i++){
			int a5 = i;
			long double v6; // fst7
			long double v7; // fst7
			__int64_t v8; // rax

			v6 = sqrt((double)a5);
			v7 = powl((long double)a5, v6);
			if ( v7 >= 9.223372036854775808e18 )
			{
				v8 = (__int64_t)(v7 - 9.223372036854775808e18);
				v8 ^= 0x8000000000000000;
			}
			else
			{
				v8 = (__int64_t)v7;
			}
			if(chars[j] == v8+21){
				printf("%c\n", i);
				break;
			}
		}
	}
}
