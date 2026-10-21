# Makefile for ChipWhisperer SimpleSerial-ChaCha20 Program
#
# Only built for the CW-Lite Arm (STM32F3) target:
#   make
#
# PLATFORM defaults to CWLITEARM; any other platform is rejected.

ifeq ($(PLATFORM),)
PLATFORM = CWLITEARM
else ifeq ($(filter $(PLATFORM),CWLITEARM CW308_STM32F3),)
$(error This project only supports the STM32F3 target (PLATFORM=CWLITEARM), got PLATFORM=$(PLATFORM))
endif

# Target file name (without extension).
TARGET = simpleserial-chacha20

# List C source files here.
SRC += simpleserial-chacha20.c chacha20.c

# ChaCha20 is self-contained, no crypto library needed
CRYPTO_TARGET = NONE

# SimpleSerial 1.1 (max. 63 data bytes per command)
SS_VER = SS_VER_1_1

#Add simpleserial project to build
include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc
