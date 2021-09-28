#include "HookAgent.h"

#ifndef __SimpleLoaderAndTransformer_h__
#define __SimpleLoaderAndTransformer_h__

namespace com_levin_commons_plugins {
    namespace jni {

#define JNI_MODE 1

#define AGENT_MODE 2

        class SimpleLoaderAndTransformer : public JavaClass {

#define INVALID_PWD_PREFIX "#INVALID_PWD:"

        public:
            SimpleLoaderAndTransformer() : JavaClass() {}

            SimpleLoaderAndTransformer(JNIEnv *env) : JavaClass(env) { initialize(env); }

            const char *getCanonicalName() const {
                return MAKE_CANONICAL_NAME(PACKAGE, SimpleLoaderAndTransformer);
            }

            /////////////////////// jni 模式 方法 ///////////////////////////////////////

            void initialize(JNIEnv *env);

            void mapFields() {}

            /////////////////////// agent 模式 方法 ///////////////////////////////////////

            void init(JavaVM *vm) const throw(AgentException);

            void parseOptions(const char *options) const throw(AgentException);

            void addCapabilities() const throw(AgentException);

            void registerEvents() const throw(AgentException);

            /////////////////////// agent 模式 方法 end ///////////////////////////////////////
        private:

            static jbyteArray aesCrypt(JNIEnv *env, jobject javaThis, jint bits,
                                       jboolean isEncrypt, jstring key, jstring iv,
                                       jbyteArray inData);

            static void JNICALL handleException(jvmtiEnv *jvmti_env,
                                                JNIEnv *env,
                                                jthread thread,
                                                jmethodID method,
                                                jlocation location,
                                                jobject exception,
                                                jmethodID catch_method,
                                                jlocation catch_location);

            /**
             * 方法进入
             * @param jvmti
             * @param env
             * @param thread
             * @param method
             */
            static void JNICALL handleMethodEntry(jvmtiEnv *jvmti,
                                                  JNIEnv *env,
                                                  jthread thread,
                                                  jmethodID method);

            /**
             * 方法退出
             * @param jvmti_env
             * @param env
             * @param thread
             * @param method
             * @param was_popped_by_exception
             * @param return_value
             */
            static void JNICALL handleMethodExit(jvmtiEnv *jvmti_env,
                                                 JNIEnv *env,
                                                 jthread thread,
                                                 jmethodID method,
                                                 jboolean was_popped_by_exception,
                                                 jvalue return_value);

        private:

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
            static jint getEnvType(JNIEnv *env, jobject javaThis, jstring key);

            /**
             *
             * 使用128位标准密码解密
             *
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
             * 使用标准密码加其它固定字符串1加密
             *
             * @param env
             * @param javaThis
             * @param password
             * @param data
             * @return
             */
            static jbyteArray transform1(JNIEnv *env, jobject javaThis, jstring password, jbyteArray data);

            /**
             *
             * 使用标准密码加其它固定字符串2加密
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


            ///////////////////////////////////////////////////////////////////////////////////////////////////////////

            static string readPwd();


            static jbyteArray aesCrypt(JNIEnv *env, jobject javaThis, jboolean isEncrypt,
                                       jboolean isHookInnerData, jbyteArray data);


            static void checkEnvSecurity();

            static void JNICALL hookClassFileLoad(jvmtiEnv *jvmti_env,
                                                  JNIEnv *env,
                                                  jclass class_being_redefined,
                                                  jobject loader,
                                                  const char *name,
                                                  jobject protection_domain,
                                                  jint class_data_len,
                                                  const unsigned char *class_data,
                                                  jint *new_class_data_len,
                                                  unsigned char **new_class_data);

            static void enableEventNotify(jvmtiEvent eventType) {
                checkException(
                        jvmtiEnvPtr->SetEventNotificationMode(JVMTI_ENABLE, eventType, (jthread) NULL));
            }


            /**
             *
             * @param filename
             * @return
             */
            static string readFile(const string &filename) {

                ifstream is(filename, ios::in);

                if (!is.is_open()) {
                    return "";
                }

                istreambuf_iterator<char> begin(is), end;

                string content(begin, end);

                is.close();

                return content;
            }

            static char *readBinaryFile(const string &filename, int &len) {

                ifstream is(filename, ios::in | ios::binary | ios::ate);

                if (!is.is_open()) {
                    return NULL;
                }

                len = is.tellg();

                is.seekg(0, ios::beg);

                char *buf = new char[len];

                is.read(buf, len);

                is.close();

                return buf;

            }

            /**
             * 覆盖文件内容
             * @param filename
             * @param content
             */
            static bool overwriteFile(const string &filename, const string &content) {

                ofstream os(filename, ios::trunc);

                if (!os.is_open()) {
                    return false;
                }

                os << content;

                os.close();

                return true;
            }

            static string getPwd(bool isHookInnerData) {
                //特意制造变量
                string time2 = "%(#Echo-21%%&##";
                time++;
                return readPwd() +
                       (isHookInnerData ? ("20l%$#@Ec" + time2 + "ho!&*21") : ("20&@&K21Ho200" + time2 + "9&*$%#oK21"));
            }

            static string getIv(bool isHookInnerData) {
                string time2 = "12-&($@^Echo*@#&";
                time--;
                return (isHookInnerData ? ("20%@$*&^@" + time2 + "ech!&*21") : "20H@HUYSR*(#" + time2 + "9&*$SaAS%#21");
            }

            /**
             *
             * @param error
             */
            static void checkException(jvmtiError error) throw(AgentException) {
                // 可以根据错误类型扩展对应的异常，这里只做简单处理
                if (error != JVMTI_ERROR_NONE) {
                    throw AgentException(error);
                }
            }

            static std::string current_working_directory() {
                char buff[512];
                GetCurrentDir(buff, 512);
                std::string current_working_directory(buff);
                return current_working_directory;
            }


            static bool isPrintLog;

            static int hashCheckFailCount;

            static int time;

            static bool overwritePwdFile;

            static jvmtiEnv *jvmtiEnvPtr;

            static string pwdFileName;

            static string pwd;

        };

    }
}

#endif // __SimpleLoaderAndTransformer_h__
