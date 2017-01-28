# Makefile for compiling HMACSHA1.java

JFLAGS = -g
JC = javac
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
        HMACSHA1.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class