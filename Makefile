EXEC=easyfw

all: $(EXEC)

$(EXEC): easyfw.c easyfw.tab.c efwlib.c
		gcc -o $@ $^ -ly

easyfw.c: easyfw.l
		flex -o $@ $^
		
easyfw.tab.c: easyfw.y
		bison -v -d -o $@ $^

clean:
	rm -f easyfw.c easyfw.tab.c easyfw.tab.h *~ $(EXEC)

