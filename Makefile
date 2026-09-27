# Forward all targets to 'just' via build.sh
.DEFAULT_GOAL := default

.PHONY: default clean test $(MAKECMDGOALS)

default:
	@./build.sh

%:
	@./build.sh $(MAKECMDGOALS)
