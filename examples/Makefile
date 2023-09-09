
all:
	javac -cp ../build/GmSSLJNI.jar HelloGmSSLJNI.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. HelloGmSSLJNI
	javac -cp ../build/GmSSLJNI.jar Sm3Example.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. Sm3Example
	javac -cp ../build/GmSSLJNI.jar Sm3HmacExample.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. Sm3HmacExample
	javac -cp ../build/GmSSLJNI.jar Sm3Pbkdf2Example.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. Sm3Pbkdf2Example
	javac -cp ../build/GmSSLJNI.jar Sm4Example.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. Sm4Example
	javac -cp ../build/GmSSLJNI.jar Sm4CbcExample.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. Sm4CbcExample
	javac -cp ../build/GmSSLJNI.jar Sm4CtrExample.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. Sm4CtrExample
	javac -cp ../build/GmSSLJNI.jar Sm4GcmExample.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. Sm4GcmExample
	javac -cp ../build/GmSSLJNI.jar ZucExample.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. ZucExample
	javac -cp ../build/GmSSLJNI.jar Sm2Example.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. Sm2Example
	javac -cp ../build/GmSSLJNI.jar Sm9Example.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. Sm9Example

clean:
	rm -fr *.class

