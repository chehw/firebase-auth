#!/bin/bash

TARGET=${1-"all"}
TARGET=$(basename ${TARGET})
TARGET=${TARGET/.[ch]/}


CC="gcc -std=gnu99 -g -Wall -D_DEBUG -Iinclude -Iutils "


case "$TARGET" in 
	all)
		echo "TODO: build all ..."
		exit 1
		;;
	firebase-auth)
		${CC} -D_TEST_FIREBASE_AUTH -D_STAND_ALONE \
			-o tests/test_${TARGET} \
			src/firebase-auth.c \
			utils/*.c \
			-lm -lpthread -ljson-c -lcurl -lpcre
		;;
	regex)
		${CC} -D_TEST_REGEX -D_STAND_ALONE \
			-o tests/test_${TARGET} \
			utils/regex.c -lpcre
		
		[ $? -ne 0 ] && exit 1
		# test
		echo "test ..."
		valgrind --leak-check=full tests/test_regex "1" "2@gmail.com" "chehw.gmail.com" "chehw@gmail.com" "1@gmail" "abc@12345678.com"
		;;
	*)
		;;
esac

