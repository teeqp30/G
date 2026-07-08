# كيفية بناء حزمة .deb للمشروع

ملفات الحزمة موجودة في packaging/debian/ ويحتوي المستودع أيضاً على plist المناسب تحت Library/MobileSubstrate/DynamicLibraries/.

خيارات البناء:

1) باستخدام Theos (موصى به):
- تأكد أن Theos مثبت ومهيأ على جهازك.
- من جذر المستودع نفّذ:
  make
  make package
- الحزمة الناتجة ستظهر في packages/ (مثلاً Wolfox_1.0-1_iphoneos-arm64.deb)

2) يدوياً (بدون Theos):
- أنشئ مجلد مؤقت لبناء الحزمة:
  mkdir -p tmp_package/DEBIAN
  mkdir -p tmp_package/Library/MobileSubstrate/DynamicLibraries
- انسخ الملفات المطلوبة:
  cp packaging/debian/control tmp_package/DEBIAN/control
  cp packaging/debian/postinst tmp_package/DEBIAN/postinst
  cp packaging/debian/prerm tmp_package/DEBIAN/prerm
  cp Library/MobileSubstrate/DynamicLibraries/Wolfox.plist tmp_package/Library/MobileSubstrate/DynamicLibraries/Wolfox.plist
  cp path/to/built/Wolfox.dylib tmp_package/Library/MobileSubstrate/DynamicLibraries/Wolfox.dylib
- اضبط الأذونات للسكربتات:
  chmod 0755 tmp_package/DEBIAN/postinst tmp_package/DEBIAN/prerm
  chmod 0644 tmp_package/DEBIAN/control
- ابني .deb:
  dpkg-deb --build tmp_package

ملاحظة: لم أضمّن ملف .dylib في المستودع لأنّ الملف يجب أن يُبنى للمعماريات المستهدفة (arm64/arm64e). بعد بناء الـ dylib باستخدام Theos أو أداة خارجية، انسخه إلى المسار المشار إليه ثم استخدم dpkg-deb أو make package.
