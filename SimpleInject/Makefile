TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SimpleInject

SimpleInject_FILES = Tweak.x
SimpleInject_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk

after-stage::
	@echo "Copying .dylib to parent directory..."
	cp $(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/$(TWEAK_NAME).dylib ../$(TWEAK_NAME)/
	@echo "Copy completed."
