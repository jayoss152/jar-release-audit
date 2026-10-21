# Original minimal example for the generated plain JVM demo. Not a Spring Boot preset.
# Paths are relative to this config's directory, independent of the caller's cwd.
-basedirectory demo/target
-injars hardened.jar
-outjars obfuscated.jar
-libraryjars <java.home>/jmods/java.base.jmod(!**.jar;!module-info.class)
-dontshrink
-dontoptimize
-keep public class Hello {
    public static void main(java.lang.String[]);
}
# Preserve class-file structures required by modern JVMs. Debug attributes are omitted.
-keepattributes StackMapTable,Exceptions,InnerClasses,EnclosingMethod,BootstrapMethods,NestHost,NestMembers,Record,PermittedSubclasses
-printmapping mapping.txt
# Keep mapping.txt private in your build system for retracing production traces.
