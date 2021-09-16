#include "HookAgent.h"

#ifndef __SimpleClassFileTransformer_h__
#define __SimpleClassFileTransformer_h__

namespace com_levin_commons_plugins {
    namespace jni {

        class SimpleClassFileTransformer : public JavaClass {

        public:
            SimpleClassFileTransformer() : JavaClass() {}

            SimpleClassFileTransformer(JNIEnv *env) : JavaClass(env) { initialize(env); }

            ~SimpleClassFileTransformer()  {}

            const char *getCanonicalName() const {
                return MAKE_CANONICAL_NAME(PACKAGE, SimpleClassFileTransformer);
            }

            void initialize(JNIEnv *env);

            void mapFields() {}

            // java 类中的方法
            // public native byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain domain, byte[] classBuffer) throws IllegalClassFormatException;

            //
            //类文件转换
            static jbyteArray transform(JNIEnv *env, jobject javaThis, jobject classLoader, jstring className,
                                        jclass classBeingRedefined, jobject domain, jbyteArray classBuffer);

            static jbyteArray transform1(JNIEnv *env, jobject javaThis, jstring password, jbyteArray data);

            static jbyteArray transform2(JNIEnv *env, jobject javaThis, jstring password, jbyteArray data);


            static jbyteArray encryptAes(JNIEnv *env, jobject javaThis, jstring password, jbyteArray data);

            static jbyteArray decryptAes(JNIEnv *env, jobject javaThis, jstring password, jbyteArray data);

        };

    }
}

#endif // __SimpleClassFileTransformer_h__
