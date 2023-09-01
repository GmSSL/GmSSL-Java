
all:
	javac -cp ../build/GmSSLJNI.jar HelloGmSSLJNI.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. HelloGmSSLJNI
	javac -cp ../build/GmSSLJNI.jar Sm3HmacExample.java
	java -Djava.library.path=../build -cp ../build/GmSSLJNI.jar:. Sm3HmacExample
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

clean:
	rm -fr *.class

