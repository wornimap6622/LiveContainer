# 探探插件 xh.dylib (免越狱, 注入 LiveContainer 内层 app)
# install_name = @executable_path/xh.dylib
TARGET := iphone:clang:latest:12.0
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = xh
xh_FILES = Tweak.m fishhook.c HelloHelper.m HelloXihuanManager.m HelloSendMgr.m \
           HelloXihuanMainViewController.m HelloCountdownLabel.m HelloGlobalBall.m \
           HelloGuowai.m HelloAuth.m HelloLocation.m
xh_FRAMEWORKS = UIKit Foundation Security AVFoundation MapKit CoreLocation AdSupport \
                 CoreTelephony CoreGraphics
xh_CFLAGS = -fobjc-arc -I$(THEOS_PROJECT_DIR) -Wno-everything
xh_LDFLAGS = -Wl,-no_fixup_chains -Wl,-install_name,@executable_path/xh.dylib -lc++ -lc++abi

include $(THEOS_MAKE_PATH)/library.mk
