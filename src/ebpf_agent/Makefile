
TARGET = agent_main

SRC_DIR = .
SRC_SUBDIR += . common config EBPFCollector EBPFWrapper flow_generator protocol_parser Sender
INCLUDE_DIR += .  ./common ./config ./EBPFCollector  ./EBPFWrapper ./flow_generator ./protocol_parser ./Sender
OBJ_DIR = .

CC = g++
C_FLAGS = -g -Wall
LD = $(CC)
INCLUDES +=  -Icommon -Iconfig -IEBPFCollector  -IEBPFWrapper -Iflow_generator -Iprotocol_parser -ISender
#INCLUDES += -I$(INCLUDE_DIR)
LD_FLAFS += -ldl
LD_LIBS =

ifeq ($(CC), g++)
	TYPE = cpp
else
	TYPE = c
endif

SRCS += ${foreach subdir, $(SRC_SUBDIR), ${wildcard $(SRC_DIR)/$(subdir)/*.$(TYPE)}}
OBJS += ${foreach src, $(notdir $(SRCS)), ${patsubst %.$(TYPE), $(OBJ_DIR)/%.o, $(src)}}

#vpath %.$(TYPE) $(sort $(dir $(SRCS)))
#SRCS_DIR = $(sort $(dir $(SRCS)))

VPATH = . util common config EBPFCollector EBPFWrapper flow_generator protocol_parser Sender

all : $(TARGET)
	@echo "Builded target:" $^
	@echo "Done"

$(TARGET) : $(OBJS)
	@mkdir -p $(@D)
	@echo "Linking" $@ "from" $^ "..." $(LD_FLAGS)
	$(LD) -o $@ $^ $(LD_FLAGS) $(LD_LIBS) -ldl
	@echo "Link finished"

$(OBJS) : $(OBJ_DIR)/%.o:%.$(TYPE)
	@echo $(OBJS)
#	@echo $(SRCS_DIR)
	@mkdir -p $(@D)
	@echo "Compiling" $@ "from" $< "..."
	$(CC) -c -o $@ $< $(C_FLAGS) $(INCLUDES)
	@echo "Compile finished"

.PHONY : clean cleanobj
clean : cleanobj
	@echo "Remove all executable files"
	rm -f $(TARGET)
cleanobj :
	@echo "Remove object files"
	rm -rf $(OBJ_DIR)/*.o






