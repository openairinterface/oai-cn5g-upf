# SPDX-License-Identifier: LicenseRef-CSSL-1.0


#              layered build system:
#                - setup       : one-time system dependency installation
#                - build       : cmake configure + compile (no dep install)
#                - rebuild     : incremental make only (fastest, no cmake)
#                - clean-xdp   : delete only BPF objects and skeletons,
#                                preserving cmake cache and all libraries
#                - clean-build : delete the full build tree (nuclear option)
#                - clean       : alias for clean-xdp (default safe clean)
#              Normal dev cycle: edit -> make rebuild
#              After BPF kernel source change: make clean-xdp && make rebuild
#              After adding new BPF programs: make build
#              First time or broken deps: make setup && make build

SHELL      := /bin/bash
GNUMAKEFLAGS = --no-print-directory

JOBS       ?= $(shell nproc)
BUILD_DIR  := build/upf/build
SKEL_DIR   := $(BUILD_DIR)/skel
BUILD_SCRIPT := build/scripts/build_upf

.PHONY: help setup build rebuild \
        clean clean-xdp clean-build \
        build-release build-debug \
        build-xdp list-targets xdp

##############################################################################
# Help
##############################################################################
help: ## Show this help message
	@printf "\n"
	@printf "\033[1mOAI UPF - Build System\033[0m\n"
	@printf "\n"
	@printf "\033[1;33mUSAGE\033[0m\n"
	@printf "  make \033[36m<target>\033[0m\n"
	@printf "\n"
	@printf "\033[1;33mINSTALLATION\033[0m\n"
	@printf "  \033[36m%-20s\033[0m %s\n" "setup" "[ONE-TIME] Install all system and build dependencies"
	@printf "\n"
	@printf "\033[1;33mBUILD\033[0m\n"
	@printf "  \033[36m%-20s\033[0m %s\n" "build"         "cmake configure + full compile (Debug)"
	@printf "  \033[36m%-20s\033[0m %s\n" "build-release" "cmake configure + full compile (Release)"
	@printf "  \033[36m%-20s\033[0m %s\n" "build-debug"   "cmake configure + full compile (Debug + verbose)"
	@printf "  \033[36m%-20s\033[0m %s\n" "rebuild"       "[FASTEST] Incremental recompile only, no cmake"
	@printf "\n"
	@printf "\033[1;33mBPF KERNEL PROGRAMS\033[0m\n"
	@printf "  \033[36m%-20s\033[0m %s\n" "build-xdp"    "Compile BPF kernel programs only (XDP .c -> skeletons)"
	@printf "  \033[36m%-20s\033[0m %s\n" "xdp"          "Wipe BPF skeletons then incremental rebuild"
	@printf "  \033[36m%-20s\033[0m %s\n" "list-targets"  "List all cmake build targets"
	@printf "\n"
	@printf "\033[1;33mCLEAN\033[0m\n"
	@printf "  \033[36m%-20s\033[0m %s\n" "clean"       "BPF skeletons only -- safe, preserves cmake cache (alias: clean-xdp)"
	@printf "  \033[36m%-20s\033[0m %s\n" "clean-xdp"   "Delete BPF skeletons and objects only"
	@printf "  \033[36m%-20s\033[0m \033[31m%s\033[0m\n" "clean-build" "[NUCLEAR] Delete entire build tree -- requires make build after"
	@printf "\n"
	@printf "\033[1;33mCOMMON WORKFLOWS\033[0m\n"
	@printf "  %-28s %s\n" "Fresh machine:"      "make setup && make build"
	@printf "  %-28s %s\n" "Everyday C++ edit:"  "make rebuild"
	@printf "  %-28s %s\n" "Kernel .c edited:"   "make build-xdp && make rebuild"
	@printf "  %-28s %s\n" "New files / cmake:"  "make build"
	@printf "  %-28s %s\n" "Broken cmake cache:" "make clean-build && make build"
	@printf "\n"

##############################################################################
# One-time system dependency installation
##############################################################################
setup: ## [ONE-TIME] Install all system and build dependencies
	$(BUILD_SCRIPT) -I -f -j -V

##############################################################################
# Full cmake configure + compile
##############################################################################
build: ## cmake configure + full compile (Debug)
	$(BUILD_SCRIPT) -j -V -b Debug

build-release: ## cmake configure + full compile (Release)
	$(BUILD_SCRIPT) -j -V -b Release

build-debug: ## cmake configure + full compile (Debug + verbose)
	$(BUILD_SCRIPT) -j -v -b Debug

##############################################################################
# Incremental recompile -- FASTEST
##############################################################################
rebuild: ## [FASTEST] Incremental recompile only (no cmake)
	@if [ ! -d "$(BUILD_DIR)" ]; then \
	  echo "ERROR: Build directory $(BUILD_DIR) does not exist."; \
	  echo "       Run 'make build' first."; \
	  exit 1; \
	fi
	$(MAKE) -C $(BUILD_DIR) -j$(JOBS)

##############################################################################
# Clean only XDP BPF skeletons and BPF object files
##############################################################################
clean-xdp: ## Delete BPF skeletons and objects only (preserves cmake cache and libs)
	@echo "Cleaning XDP skeletons and BPF objects only..."
	@rm -rf $(SKEL_DIR)
	@find $(BUILD_DIR) -name "*.bpf.o" -delete 2>/dev/null || true
	@find $(BUILD_DIR) -name "*_skel.h" -delete 2>/dev/null || true
	@find $(BUILD_DIR) -name "xdp_*.o"  -delete 2>/dev/null || true
	@echo "Done. BPF skeletons removed. Run 'make rebuild' to regenerate."

##############################################################################
# Nuclear clean
##############################################################################
clean-build: ## [NUCLEAR] Delete entire build tree (requires 'make build' after)
	@echo "Deleting entire build tree: $(BUILD_DIR)"
	@rm -rf $(BUILD_DIR)
	@mkdir -m 777 -p $(BUILD_DIR)
	@echo "Done. Run 'make build' to rebuild from scratch."

##############################################################################
# Default clean = clean-xdp (safe, fast)
##############################################################################
clean: clean-xdp ## Default clean: BPF skeletons only (safe). Use clean-build for full wipe.

##############################################################################
# List all available cmake build targets
##############################################################################
list-targets: ## List all cmake build targets
	@if [ ! -d "$(BUILD_DIR)" ]; then \
	  echo "ERROR: Run 'make build' first to generate cmake targets."; \
	  exit 1; \
	fi
	@echo "Available cmake targets:"
	@$(MAKE) -C $(BUILD_DIR) help 2>/dev/null | grep -i "bpf\|xdp\|skel\|upf" || \
	  $(MAKE) -C $(BUILD_DIR) help

##############################################################################
# Compile only the BPF kernel programs (XDP .c -> .o -> skeleton .h)
##############################################################################
build-xdp: ## Compile BPF kernel programs only (XDP .c -> skeletons)
	@if [ ! -d "$(BUILD_DIR)" ]; then \
	  echo "ERROR: Build directory $(BUILD_DIR) does not exist."; \
	  echo "       Run 'make build' first."; \
	  exit 1; \
	fi
	@echo "Compiling BPF kernel programs..."
	$(MAKE) -C $(BUILD_DIR) -j$(JOBS) upf_xdp_all
	@echo "BPF compilation done. Run 'make rebuild' to recompile userspace."

xdp: clean-xdp rebuild ## Wipe BPF skeletons then incremental rebuild (BPF source changed)