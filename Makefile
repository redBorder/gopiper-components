COMPONENTS= pcap multiudp
BUILD_DIR=  build

build: $(PLUGINS) build_dir
	@for component in $(COMPONENTS); do \
		cd $$component && make && cd ..; \
		mv $$component/*.so $(BUILD_DIR)/; \
	done

build_dir: $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)

clean: $(PLUGINS)
	@for component in $(COMPONENTS); do \
		cd $$component && rm -rf vendor && cd ..; \
	done
	rm -rf $(BUILD_DIR)
