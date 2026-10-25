# Keep engine interface names — plugins resolve them reflectively by capability id.
-keep interface com.sentinelnet.engine.api.** { *; }
-keep class com.sentinelnet.core.model.** { *; }
-keepattributes Signature, *Annotation*
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
