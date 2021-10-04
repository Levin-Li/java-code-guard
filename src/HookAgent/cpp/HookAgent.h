
#ifndef __HookAgent_h__
#define __HookAgent_h__

#include <iostream>
#include <fstream>
#include <iosfwd>
#include <regex>
#include <iterator>
#include<chrono>
#include<thread>

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

extern jint envType;

extern bool isPrintLog;
///////////////////////////// JNI ////////////////////////////////////////
//头文件只能申明全局变量（extern），不可定义（不推荐使用）
//extern ClassRegistry gClasses;

//JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved);

//JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved);

//////////////////////////// JVMTI AGENT ////////////////////////////////////////////

/**
 * jvmtiEnvPtr agent onload
 * @param vm
 */
//JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved);

/**
 * jvmtiEnvPtr agent attach
 * @param vm
 */
//JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved);

/**
 * jvmtiEnvPtr agent unload
 * @param vm
 */
//JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm);

////////////////////////////////////////////////////////////////////////

namespace com_levin_commons_plugins {
    namespace jni {

        class AgentException : public exception {
            const char *errInfo = "AgentException";
        public:
            explicit AgentException(jvmtiError err) : exception() {
                m_error = err;
            }

            char *what() const throw() override {
                return const_cast<char *>(errInfo);
            }

            jvmtiError ErrCode() const throw() {
                return m_error;
            }

        private:
            jvmtiError m_error;
        };

    }
}
#endif // __HookAgent_h__
