MKL_RED?=	\033[031m
MKL_GREEN?=	\033[032m
MKL_YELLOW?=	\033[033m
MKL_BLUE?=	\033[034m
MKL_CLR_RESET?=	\033[0m

COMPONENT= pcap_component.so

build:
	@printf "$(MKL_YELLOW)[BUILD]$(MKL_CLR_RESET)    Building $(COMPONENT)\n"
	@go build \
		-ldflags "-X main.version=`git describe --tags --always --dirty=-dev`" \
		-buildmode=plugin -o $(COMPONENT)
