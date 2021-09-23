#include "HookAgent.h"

#ifndef __SimpleLoaderAndTransformer_h__
#define __SimpleLoaderAndTransformer_h__

namespace com_levin_commons_plugins {
    namespace jni {

        class SimpleLoaderAndTransformer : public JavaClass {

        public:
            SimpleLoaderAndTransformer() : JavaClass() {}

            SimpleLoaderAndTransformer(JNIEnv *env) : JavaClass(env) { initialize(env); }

            ~SimpleLoaderAndTransformer() {}

            const char *getCanonicalName() const {
                return MAKE_CANONICAL_NAME(PACKAGE, SimpleLoaderAndTransformer);
            }

            void initialize(JNIEnv *env);

            void mapFields() {}

            /**
             * 设置密码
             * @param env
             * @param javaThis
             * @param pwd
             * @param pwdFileName
             */
            static void setPwd(JNIEnv *env, jobject javaThis, jstring pwd, jstring pwdFileName);


            /**
             *
             * @param env
             * @param javaThis
             * @param name
             * @return
             */
            static jclass findClass(JNIEnv *env, jobject javaThis, jstring name);

            /**
             *
             * @param env
             * @param javaThis
             * @return
             */
            static jint getEnvType(JNIEnv *env, jobject javaThis);


            /**
             *
             * @param env
             * @param javaThis
             * @param classLoader
             * @param className
             * @param classBeingRedefined
             * @param domain
             * @param classBuffer
             * @return
             */
            static jbyteArray transform(JNIEnv *env, jobject javaThis, jobject classLoader, jstring className,
                                        jclass classBeingRedefined, jobject domain, jbyteArray classBuffer);

            /**
             * 内部数据加密方法
             * @param env
             * @param javaThis
             * @param password
             * @param data
             * @return
             */
            static jbyteArray transform1(JNIEnv *env, jobject javaThis, jstring password, jbyteArray data);

            /**
             *
             * @param env
             * @param javaThis
             * @param password
             * @param data
             * @return
             */
            static jbyteArray transform2(JNIEnv *env, jobject javaThis, jstring password, jbyteArray data);

            /**
             * 通用加密方法
             * @param env
             * @param javaThis
             * @param password
             * @param data
             * @return
             */
            static jbyteArray encryptAes(JNIEnv *env, jobject javaThis, jint bits, jstring password, jbyteArray data);

            /**
             * 通用解密方法
             * @param env
             * @param javaThis
             * @param password
             * @param data
             * @return
             */
            static jbyteArray decryptAes(JNIEnv *env, jobject javaThis, jint bits, jstring password, jbyteArray data);

        };

    }
}

#endif // __SimpleLoaderAndTransformer_h__