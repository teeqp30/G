include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Wolfox
Wolfox_FILES = Tweak.x
Wolfox_FRAMEWORKS = Foundation UIKit MapKit CoreLocation CoreBluetooth
Wolfox_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "sbreload || killall -9 SpringBoard || true"
