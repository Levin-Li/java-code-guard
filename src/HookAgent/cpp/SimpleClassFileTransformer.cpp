#include "SimpleClassFileTransformer.h"

namespace com_levin_commons_plugins {
    namespace jni {

        void SimpleClassFileTransformer::initialize(JNIEnv *env) {

            setClass(env);

            //增加 JNI
            //注意参数列表需要用 NULL 结尾，表示参数结束

            addNativeMethod("transform1", (void *) transform1, kTypeArray(kTypeByte), kTypeString,
                            kTypeArray(kTypeByte), NULL);

            addNativeMethod("transform2", (void *) transform2, kTypeArray(kTypeByte), kTypeString,
                            kTypeArray(kTypeByte), NULL);

            addNativeMethod("encryptAes", (void *) encryptAes, kTypeArray(kTypeByte), kTypeString,
                            kTypeArray(kTypeByte), NULL);
            addNativeMethod("decryptAes", (void *) decryptAes, kTypeArray(kTypeByte), kTypeString,
                            kTypeArray(kTypeByte), NULL);

            addNativeMethod("transform", (void *) transform, kTypeArray(kTypeByte), kTypeJavaClass(ClassLoader),
                            kTypeString, kTypeJavaClass(Class), "java/security/ProtectionDomain", kTypeArray(kTypeByte),
                            NULL);
            //注册到 JNI
            registerNativeMethods(env);
        }

        jbyteArray
        SimpleClassFileTransformer::transform1(JNIEnv *env, jobject javaThis, jstring password, jbyteArray data) {

            return HookAgent::aesCrypt(env, javaThis, JNI_TRUE, data);

        }

        jbyteArray
        SimpleClassFileTransformer::transform2(JNIEnv *env, jobject javaThis, jstring password, jbyteArray data) {

            JavaString pwd(HookAgent::readPwd() +"" +password);

            return HookAgent::aesCrypt(env, javaThis, 192, JNI_TRUE, pwd.toJavaString(env).leak(), data);
        }

        /**
         * 转换类问卷内容
         * @param env
         * @param javaThis
         * @param classLoader
         * @param className
         * @param classBeingRedefined
         * @param domain
         * @param classBuffer
         * @return
         */
        jbyteArray
        SimpleClassFileTransformer::transform(JNIEnv *env, jobject javaThis, jobject classLoader, jstring className,
                                              jclass classBeingRedefined, jobject domain, jbyteArray classBuffer) {

            if (classLoader == NULL || className == NULL
                || classBuffer == NULL || env->GetArrayLength(classBuffer) < 1) {
                return NULL;
            }

            //使用默认密码解密
            return decryptAes(env, javaThis, env->NewStringUTF(HookAgent::readPwd().c_str()), classBuffer);
        }

        jbyteArray
        SimpleClassFileTransformer::decryptAes(JNIEnv *env, jobject javaThis, jstring password, jbyteArray data) {
            return HookAgent::aesCrypt(env, javaThis, 128, JNI_FALSE, password, data);
        }

        jbyteArray
        SimpleClassFileTransformer::encryptAes(JNIEnv *env, jobject javaThis, jstring password, jbyteArray data) {
            return HookAgent::aesCrypt(env, javaThis, 128, JNI_TRUE, password, data);
        }

    }
}