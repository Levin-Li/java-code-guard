
#ifndef __HookAgent_h__
#define __HookAgent_h__

#include <iostream>
#include <fstream>
#include <iosfwd>
#include <regex>
#include <iterator>
#include<chrono>
#include<thread>

#import<filesystem>

#include "jvmti.h"
#include "jni.h"
#include "AES.h"
#include "md5.h"
#include "JniHelpers.h"


//Java 类包名
#define PACKAGE "com/levin/commons/plugins/jni"

#define HELPER_CLASS PACKAGE "/JniHelper"
#define HOOK_CLASS   PACKAGE "/HookAgent"

//关于变量的定义和声明
//声明可以多次，定义只能有一次
//定义包含声明

//如果是要定义全局变量，那么在头文件中用extern关键字声明，然后在另一个.cpp文件中定义；
//如果是要声明一个不想被其他文件使用、只能被本文件使用的变量，可以用static关键字在头文件中进行定义；
//如果所要定义的变量为局部变量，并且其值在编译时就已经可以确定，就可以用const关键词在头文件中进行定义。

//int a;//定义
//extern int a;//声明
//extern int a =0 ;//定义


#if defined(_MSC_VER)
#include <direct.h>
#define GetCurrentDir _getcwd
#else
//#elif defined(__unix__)
#include <unistd.h>

#define GetCurrentDir getcwd
#endif


//包名定义
namespace com_levin_commons_plugins {
    namespace jni {
    }
}

using namespace std;
using namespace spotify::jni;
using namespace com_levin_commons_plugins::jni;

//////////////////////////////////////////////////////////////////////////
//
extern jclass hookClass;

extern jint envType;

///////////////////////////// JNI ////////////////////////////////////////
//头文件只能申明全局变量（extern），不可定义（不推荐使用）
//extern ClassRegistry gClasses;

//JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved);

//JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved);

//////////////////////////// JVMTI AGENT ////////////////////////////////////////////

/**
 * jvmti_env agent onload
 * @param vm
 */
//JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved);

/**
 * jvmti_env agent attach
 * @param vm
 */
//JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved);

/**
 * jvmti_env agent unload
 * @param vm
 */
//JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm);

////////////////////////////////////////////////////////////////////////

namespace com_levin_commons_plugins {
    namespace jni {

        class AgentException : public exception {
            const char *errInfo = "AgentException";
        public:
            AgentException(jvmtiError err) : exception() {
                m_error = err;
            }

            char *what() const throw() {
                return const_cast<char *>(errInfo);
            }

            jvmtiError ErrCode() const throw() {
                return m_error;
            }

        private:
            jvmtiError m_error;
        };


        class HookAgent {

#define INVALID_PWD_PREFIX "#INVALID_PWD:"

        public:

            HookAgent() throw(AgentException) {}

            ~HookAgent() throw(AgentException);

            void init(JavaVM *vm) const throw(AgentException);

            void parseOptions(const char *str) const throw(AgentException);

            void addCapabilities() const throw(AgentException);

            void registerEvents() const throw(AgentException);

            static string readPwd();

            static void setPwd(JNIEnv *env, jobject javaThis, jstring pwd, jstring pwdFileName);

            static jbyteArray
            aesCrypt(JNIEnv *env, jobject javaThis, jboolean isEncrypt, jboolean isHookInnerData, jbyteArray data);


            static jbyteArray
            aesCrypt(JNIEnv *env, jobject javaThis, jint bits, jboolean isEncrypt, jstring key, jstring iv,
                     jbyteArray inData);

            static jclass findClass(JNIEnv *env, jobject javaThis, jstring name);

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
                        jvmti_env->SetEventNotificationMode(JVMTI_ENABLE, eventType, (jthread) NULL));
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

            static void trimAndRemoveWhiteSpace(string &s) {

                if (s.empty()) {
                    return;
                }

                s.erase(0, s.find_first_not_of(" "));
                s.erase(s.find_last_not_of(" ") + 1);

                regex pattern("\r|\n|\t");

                string r = regex_replace(s, pattern, "");

                s.clear();

                s.append(r);
            }

            static int time;

            static bool overwritePwdFile;

            static jvmtiEnv *jvmti_env;

            static string pwdFileName;

            static string pwd;
        };

    }
}
#endif // __HookAgent_h__
