NAME = dhcp_stats
TARGET = dhcp-stats
FLAGS = -lpcap
CC = gcc

all: $(NAME).c
	$(CC) -o $(TARGET) $(NAME).c  $(FLAGS)

clean:
	rm -f $(TARGET)