# DEX / APK Method Patcher (Rust)

Высокопроизводительный инструмент на Rust для прямого модифицирования байткода DEX в APK, JAR и отдельных `.dex` файлах.

## Преимущества над apktool / smali:
- **Скорость:** Патчит методы за **~1.4 секунды** на 100MB+ APK без декомпиляции в smali и повторной сборки (вместо нескольких минут работы Java/apktool).
- **Безопасность байткода:** Не повреждает выравнивание 4KB/16KB uncompressed `.so` библиотек.
- **Автономность:** Не требует Java, Android SDK или python-скриптов.
- **Поддержка нескольких методов:** Позволяет передавать методы через запятую (`addViews,applyConstraints,bindData,removeViews`) или `*`.

## Использование:
```bash
dex_patcher <input_file> <class_pattern> <method_name(s)> <void|true|false> [output_file]
```

### Примеры:
```bash
# Патч краша Dark Mode в ColorOS 17 SystemUI (DefaultSettingsPopupMenuSection)
dex_patcher SystemUI.apk DefaultSettingsPopupMenuSection addViews,applyConstraints,bindData,removeViews void

# Отключение проверки подписи в services.jar
dex_patcher services.jar ScanPackageUtils assertMinSignatureSchemeIsValid void

# Включение AOD фич
dex_patcher SystemUI.apk SmoothTransitionController isSupportMyDevice true
```
