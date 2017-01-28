# Makefile for compiling AESCBC.java and AESCTR.java

JFLAGS = -g
JC = javac
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
        AESCTR.java \
        AESCBC.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class