# XHSpoof 通用设备指纹随机化 tweak（纯自写，无卡密）
# arm64 + arm64e 双架构，install_name 任意（作为 tweak 由 loader dlopen）
TARGET := iphone:clang:latest:8.0
ARCHS := arm64 arm64e
include $(THEOS)/makefiles/common.mk
LIBRARY_NAME = XHSpoof
XHSpoof_FILES = XHSpoof.m fishhook.c
XHSpoof_FRAMEWORKS = UIKit Foundation Security CoreTelephony
XHSpoof_CFLAGS = -fobjc-arc -Wno-unused-function -Wno-unused-variable -Wno-deprecated-declarations
XHSpoof_LDFLAGS = -Wl,-no_fixup_chains -lc++ -lc++abi
include $(THEOS_MAKE_PATH)/library.mk
