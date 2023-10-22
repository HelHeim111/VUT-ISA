NAME = dhcp_stats
TARGET = dhcp-stats
CC = gcc

all: $(NAME).c
	$(CC) -o $(TARGET) $(NAME).c

clean:
	rm -f $(TARGET)