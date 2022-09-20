################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/Raichoo.cpp \
../src/context.cpp \
../src/gen.cpp \
../src/hash.cpp \
../src/random.cpp \
../src/signer.cpp \
../src/user.cpp \
../src/ver.cpp 

CPP_DEPS += \
./src/Raichoo.d \
./src/context.d \
./src/gen.d \
./src/hash.d \
./src/random.d \
./src/signer.d \
./src/user.d \
./src/ver.d 

OBJS += \
./src/Raichoo.o \
./src/context.o \
./src/gen.o \
./src/hash.o \
./src/random.o \
./src/signer.o \
./src/user.o \
./src/ver.o 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.cpp src/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-src

clean-src:
	-$(RM) ./src/Raichoo.d ./src/Raichoo.o ./src/context.d ./src/context.o ./src/gen.d ./src/gen.o ./src/hash.d ./src/hash.o ./src/random.d ./src/random.o ./src/signer.d ./src/signer.o ./src/user.d ./src/user.o ./src/ver.d ./src/ver.o

.PHONY: clean-src

