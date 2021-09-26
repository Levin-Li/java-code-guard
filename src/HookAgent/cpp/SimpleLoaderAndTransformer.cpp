#include "SimpleLoaderAndTransformer.h"


namespace com_levin_commons_plugins {
    namespace jni {

        void SimpleLoaderAndTransformer::initialize(JNIEnv *env) {

            setClass(env);

            //增加 JNI
            //注意参数列表需要用 NULL 结尾，表示参数结束

            addNativeMethod("getEnvType", (void *) getEnvType, kTypeInt, NULL);

            addNativeMethod("setPwd", (void *) setPwd, kTypeVoid, kTypeString, kTypeString, NULL);

            addNativeMethod("transform1", (void *) transform1, kTypeArray(kTypeByte), kTypeString,
                            kTypeArray(kTypeByte), NULL);

            addNativeMethod("transform2", (void *) transform2, kTypeArray(kTypeByte), kTypeString,
                            kTypeArray(kTypeByte), NULL);

            addNativeMethod("findClass", (void *) findClass, kTypeJavaClass(Class), kTypeString, NULL);

            addNativeMethod("transform", (void *) transform, kTypeArray(kTypeByte), kTypeJavaClass(ClassLoader),
                            kTypeString, kTypeJavaClass(Class), "java/security/ProtectionDomain", kTypeArray(kTypeByte),
                            NULL);

            addNativeMethod("encryptAes", (void *) encryptAes, kTypeArray(kTypeByte), kTypeInt, kTypeString,
                            kTypeArray(kTypeByte), NULL);

            addNativeMethod("decryptAes", (void *) decryptAes, kTypeArray(kTypeByte), kTypeInt, kTypeString,
                            kTypeArray(kTypeByte), NULL);

            //注册到 JNI
            registerNativeMethods(env);
        }


        jint SimpleLoaderAndTransformer::getEnvType(JNIEnv *env, jobject javaThis) {
            return envType;
        }

        jbyteArray SimpleLoaderAndTransformer::transform1(JNIEnv *env, jobject javaThis,
                                                          jstring password, jbyteArray data) {
            return aesCrypt(env, javaThis, JNI_TRUE, JNI_TRUE, data);
        }

        jbyteArray SimpleLoaderAndTransformer::transform2(JNIEnv *env, jobject javaThis,
                                                          jstring password, jbyteArray data) {
            return aesCrypt(env, javaThis, JNI_TRUE, JNI_FALSE, data);
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
        jbyteArray SimpleLoaderAndTransformer::transform(JNIEnv *env, jobject javaThis,
                                                         jobject classLoader, jstring className,
                                                         jclass classBeingRedefined, jobject domain,
                                                         jbyteArray classBuffer) {

            if (className == NULL
                || classBuffer == NULL || env->GetArrayLength(classBuffer) < 1) {
                return NULL;
            }

            //使用默认密码解密
            jstring pwd = env->NewStringUTF(readPwd().c_str());

            jbyteArray outData = decryptAes(env, javaThis, 128, pwd, classBuffer);

            env->DeleteLocalRef(pwd);

            return outData;
        }

        jbyteArray SimpleLoaderAndTransformer::decryptAes(JNIEnv *env, jobject javaThis,
                                                          jint bits, jstring password, jbyteArray data) {
            return aesCrypt(env, javaThis, bits, JNI_FALSE, password, NULL, data);
        }

        jbyteArray SimpleLoaderAndTransformer::encryptAes(JNIEnv *env, jobject javaThis,
                                                          jint bits, jstring password, jbyteArray data) {
            return aesCrypt(env, javaThis, bits, JNI_TRUE, password, NULL, data);
        }
    }
}
