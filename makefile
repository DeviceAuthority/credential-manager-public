# Builds libnauddk_shared and all dependencies.

.PHONY: all clean

all:
	$(MAKE) -f make_agent.mk
clean:
	$(MAKE) -f make_agent.mk clean
