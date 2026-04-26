# ─── Strip logging in release ──────────────────────────────────────
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

# ─── BouncyCastle (classical) ──────────────────────────────────────
-keep class org.bouncycastle.** { *; }
-keep interface org.bouncycastle.** { *; }
-keepclassmembers class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**

# ─── BouncyCastle PQC — accessed via reflection, must keep all ─────
-keep class org.bouncycastle.pqc.** { *; }
-keep interface org.bouncycastle.pqc.** { *; }
-keepclassmembers class org.bouncycastle.pqc.** { *; }

# JCE providers are looked up reflectively by string name + class name.
-keepnames class * extends java.security.Provider
-keepnames class * extends java.security.Provider$Service

# Preserve algorithm-spec static fields (Kyber.kyber768 etc)
-keepclassmembers class org.bouncycastle.pqc.jcajce.spec.** {
    public static <fields>;
}
-keepclassmembers class org.bouncycastle.jcajce.spec.** {
    public static <fields>;
}

# ─── Compose ───────────────────────────────────────────────────────
-keep class androidx.compose.** { *; }

# ─── Kotlin metadata ───────────────────────────────────────────────
-keep class kotlin.Metadata { *; }

# ─── Attributes ────────────────────────────────────────────────────
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable,Signature,InnerClasses,EnclosingMethod,*Annotation*
