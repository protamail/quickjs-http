OBJDIR=.obj

CC=gcc
#-flto 
CFLAGS=-g -O2 -Wall -MMD -MF $(OBJDIR)/$(@F).d -I/usr/lib/jvm/java/include -I/usr/lib/jvm/java/include/linux -I/opt/app/workload/addon/java/jdk1.8.0_144/include -I/opt/app/workload/addon/java/jdk1.8.0_144/include/linux
CFLAGS += -Wno-array-bounds -Wno-format-truncation
AR=gcc-ar
STRIP=strip
LDFLAGS=-g
SHLIB=libhttputil.so

PROGS=$(SHLIB)

all: $(PROGS)

LIB_OBJS=$(OBJDIR)/http-util.o $(OBJDIR)/http_parser.o

LIBS=-lm -ldl -lrt

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(SHLIB): $(OBJDIR) $(LIB_OBJS)
	$(CC) $(LDFLAGS) -shared -o $@ $(LIB_OBJS) $(LIBS)
#	$(STRIP) $@

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) -fPIC -DJS_SHARED_LIBRARY -c -o $@ $<

clean:
	rm -rf $(OBJDIR)/ $(PROGS)

test: all


