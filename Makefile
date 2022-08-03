all:
	gcc -shared -fPIC -Wall -I./jni GmSSL.c -lgmssl -o libgmssljni.dylib
	javac org/gmssl/GmSSL.java

test:
	java org.gmssl.GmSSL

clean:
	rm -f libgmssljni.dylib
	rm -f org/gmssl/GmSSL.class

