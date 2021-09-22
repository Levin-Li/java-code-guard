
#include "HookAgent.h"

#include "SimpleClassFileTransformer.h"

// 注意 jni 和 jvmti agent 的接口 都不允许在名称空间里面

/////////////////////////////// JNI Interface /////////////////////////////////////
ClassRegistry gClasses;

jclass hookClass;

jint envType = 0;

////////////////////////////////////////////////////////////////////////////////////
void checkVMOptions(JavaVM *jvm, JNIEnv *env) {

    //    jint JNI_GetDefaultJavaVMInitArgs(void *vm_args);
//
//    vm_args：JavaVMInitArgs类型的参数，该结构体声明在10.2.1
//    return：获取成功返回JNI_OK，失败返回其他。

    JavaVMInitArgs vmInitArgs;

    memset(&vmInitArgs, 0, sizeof(struct JavaVMInitArgs));

    jint result = JNI_ERR;// JNI_GetDefaultJavaVMInitArgs(&vmInitArgs);

    if (result != JNI_OK) {
        return;
    }

    cout << "vmInitArgs version:" << vmInitArgs.version << " nOptions: " << vmInitArgs.nOptions << endl;

    int n = 0;

    while (n++ < vmInitArgs.nOptions) {
        cout << " Options " << n << vmInitArgs.options[n - 1].optionString << endl;
    }

}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) {

    LOG_INFO("Initializing JNI");
    JNIEnv *env = jniHelpersInitialize(jvm);

    if (env == NULL) {
        return -1;
    }

    if (envType == 0) {
        envType = 2;
    }

    gClasses.add(env, new SimpleClassFileTransformer(env));

    cout << " JNI_OnLoad " << JAVA_VERSION << endl;

    checkVMOptions(jvm, env);

    LOG_INFO("Initialization complete");
    return JAVA_VERSION;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    printf("%s\n", "JNI_OnUnload");
}

//////////////////////////// jvmit agent ///////////////////////////////////////

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {

    cout << "Agent_OnLoad(" << vm << ") " << options << endl;

    if (envType == 0) {
        envType = 1;
    }

    checkVMOptions(vm, NULL);

    try {

        HookAgent *agent = new HookAgent();

        agent->init(vm);

        agent->parseOptions(options);

        agent->addCapabilities();

        agent->registerEvents();

    } catch (AgentException &e) {
        cout << "Error when enter HandleMethodEntry: " << e.what() << " [" << e.ErrCode() << "]" << endl;
        return JNI_ERR;
    }

    return JNI_OK;
}

JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    printf("%s\n", "Agent_OnAttach");
    return JNI_OK;
}

JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    printf("%s\n", "Agent_OnUnload");
}

///////////////////////////////////////////////////////////////////

namespace com_levin_commons_plugins {
    namespace jni {

        bool HookAgent::overwritePwdFile = true;

        jvmtiEnv *HookAgent::jvmti_env = NULL;
        string HookAgent::pwdFileName = "";
        string HookAgent::pwd = "";

        int HookAgent::time = 202109;
        //密码

        HookAgent::~HookAgent() throw(AgentException) {
            // 必须释放内存，防止内存泄露
        }

        void HookAgent::init(JavaVM *vm) const throw(AgentException) {

            jvmtiEnv *jvmti = NULL;

            jint ret = (vm)->GetEnv(reinterpret_cast<void **>(&jvmti), JVMTI_VERSION_1_2); //JVMTI_VERSION

            if (ret != JNI_OK || jvmti == NULL) {
                throw AgentException(JVMTI_ERROR_INTERNAL);
            }

            jvmti_env = jvmti;
        }


        void HookAgent::parseOptions(const char *str) const throw(class AgentException) {

            if (str == NULL)
                return;

            const size_t len = strlen(str);

            if (len == 0)
                return;

            pwdFileName = str;

            cout << "options:" + pwdFileName + " " << overwritePwdFile << endl;

            readPwd();
        }

        void HookAgent::addCapabilities() const throw(class AgentException) {

            // 创建一个新的环境
            jvmtiCapabilities caps;

            memset(&caps, 0, sizeof(caps));

            caps.can_generate_method_entry_events = JVMTI_ENABLE;
            caps.can_generate_method_exit_events = JVMTI_ENABLE;

            caps.can_generate_all_class_hook_events = JVMTI_ENABLE;

            caps.can_generate_exception_events = JVMTI_ENABLE;

            caps.can_redefine_classes = JVMTI_ENABLE;
            caps.can_redefine_any_class = JVMTI_ENABLE;
            caps.can_retransform_classes = JVMTI_ENABLE;
            caps.can_retransform_any_class = JVMTI_ENABLE;

            // 设置当前环境
            checkException(jvmti_env->AddCapabilities(&caps));
        }

        void HookAgent::registerEvents() const throw(class AgentException) {

            // 创建一个新的回调函数
            jvmtiEventCallbacks callbacks;

            memset(&callbacks, 0, sizeof(callbacks));

            callbacks.MethodEntry = &HookAgent::handleMethodEntry;
            callbacks.MethodExit = &HookAgent::handleMethodExit;

            callbacks.ClassFileLoadHook = &HookAgent::hookClassFileLoad;
            callbacks.Exception = &HookAgent::handleException;

            // 设置回调函数
            checkException(jvmti_env->SetEventCallbacks(&callbacks, static_cast<jint>(sizeof(callbacks))));

            // 开启事件监听
            enableEventNotify(JVMTI_EVENT_METHOD_ENTRY);
            enableEventNotify(JVMTI_EVENT_METHOD_EXIT);
            enableEventNotify(JVMTI_EVENT_CLASS_FILE_LOAD_HOOK);
            enableEventNotify(JVMTI_EVENT_EXCEPTION);

        }

        void HookAgent::setPwd(JNIEnv *env, jobject javaThis, jstring pwdStr, jstring pwdFileNameStr) {

            if (pwdStr != NULL) {
                pwd = (new JavaString(env, pwdStr))->get();
                trimAndRemoveWhiteSpace(pwd);
            }

            if (pwdFileNameStr != NULL) {
                pwdFileName = (new JavaString(env, pwdFileNameStr))->get();
                trimAndRemoveWhiteSpace(pwdFileName);
            }
        }

        string HookAgent::readPwd() {

            if (!pwd.empty()) {
                return pwd;
            }

            trimAndRemoveWhiteSpace(pwdFileName);

            if (pwdFileName.empty()) {
                pwdFileName = ".java_agent/.pwdFile.txt";
            }

            //静态密码
            //从文件读取动态密码
            pwd = readFile(pwdFileName);

            trimAndRemoveWhiteSpace(pwd);

            if (pwd.empty() || pwd.find_first_of(INVALID_PWD_PREFIX) != string::npos) {

                cerr << "pwd file " << current_working_directory() << "/" << pwdFileName << " not exist or invalid. "
                     << pwd << endl;;

                pwd = "";

            } else if (overwritePwdFile) {
                //覆盖密码文件内容
                int n = 0;

                while (n++ < 15 && !overwriteFile(pwdFileName, string(INVALID_PWD_PREFIX) + "#pwd already read.")) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                    //如果文件覆盖失败
                }

                if (n >= 15) {
                    //如果文件覆盖失败
                    pwd = "";
                }

            }

            return pwd;
        }


//        3、异常处理的相关JNI函数总结：
//        1> ExceptionCheck：检查是否发生了异常，若有异常返回JNI_TRUE，否则返回JNI_FALSE
//        2> ExceptionOccurred：检查是否发生了异常，若用异常返回该异常的引用，否则返回NULL
//        3> ExceptionDescribe：打印异常的堆栈信息
//        4> ExceptionClear：清除异常堆栈信息
//        5> ThrowNew：在当前线程触发一个异常，并自定义输出异常信息
//                jint (JNICALL *ThrowNew) (JNIEnv *env, jclass clazz, const char *msg);
//        6> Throw：丢弃一个现有的异常对象，在当前线程触发一个新的异常
//                jint (JNICALL *Throw) (JNIEnv *env, jthrowable obj);
//        7> FatalError：致命异常，用于输出一个异常信息，并终止当前VM实例（即退出程序）
//        void (JNICALL *FatalError) (JNIEnv *env, const char *msg);


        jobject invoke(JNIEnv *env, jobject instance, const char *methodName, const char *methodSign, ...) {

            jclass clazz = env->GetObjectClass(instance);

            jmethodID jmethodId = env->GetMethodID(clazz, methodName, methodSign);

            // cout << "class " << clazz << " " << methodName << methodSign << " jmethodId: " << jmethodId << endl;

            jobject result = NULL;

            va_list args;

            va_start(args, methodSign);

            if (string(methodSign).find_last_of("V") != string::npos) {
                env->CallVoidMethodV(instance, jmethodId, args);
            } else {
                result = env->CallObjectMethodV(instance, jmethodId, args);
            }

            va_end(args);

            env->DeleteLocalRef(clazz);

            //注意！！！，方法ID 不可释放，否则虚拟机会异常退出
            // free(jmethodId);

            return result;
        }

        jint invokeInt(JNIEnv *env, jobject instance, const char *methodName, const char *methodSign, ...) {

            jclass clazz = env->GetObjectClass(instance);

            jmethodID jmethodId = env->GetMethodID(clazz, methodName, methodSign);

            va_list args;
            jint result;

            va_start(args, methodSign);

            result = env->CallIntMethodV(instance, jmethodId, args);

            va_end(args);

            env->DeleteLocalRef(clazz);

            return result;
        }


        jobject invokeStatic(JNIEnv *env, const char *className, const char *methodName, const char *methodSign, ...) {

            jclass clazz = env->FindClass(className);

            jmethodID jmethodId = env->GetStaticMethodID(clazz, methodName, methodSign);

            va_list args;
            jobject result;

            va_start(args, methodSign);

            result = env->CallStaticObjectMethodV(clazz, jmethodId, args);

            va_end(args);

            env->DeleteLocalRef(clazz);

            return result;
        }

        string &replace_all_distinct(string &str, const string &old_value, const string &new_value) {
            for (string::size_type pos(0); pos != string::npos; pos += new_value.length()) {
                if ((pos = str.find(old_value, pos)) != string::npos)
                    str.replace(pos, old_value.length(), new_value);
                else break;
            }
            return str;
        }


        jobject getClassLoader(JNIEnv *env, jobject loader) {

            if (loader == NULL) {

                jobject thread = invokeStatic(env, "java/lang/Thread", "currentThread", "()Ljava/lang/Thread;");

                loader = invoke(env, thread, "getContextClassLoader", "()Ljava/lang/ClassLoader;");

                env->DeleteLocalRef(thread);

                cerr << "try get current thread Context ClassLoader" << endl;
            }

            if (loader == NULL) {

                loader = invokeStatic(env, "java/lang/ClassLoader", "getSystemClassLoader",
                                      "()Ljava/lang/ClassLoader;");

                cerr << "try get System ClassLoader" << endl;
            }

            return loader;
        }

        unsigned char *autoNew(unsigned char *data, const size_t requireLen) {

            size_t len = strlen((const char *) (data));

            auto *newData = (unsigned char *) malloc(requireLen + 1);

            memset(newData, '*', requireLen);

            //复制内存
            memcpy(newData, data, len >= requireLen ? requireLen : len);

            //设置结束
            newData[requireLen] = 0;

            return newData;
        }


        /**
         * 核心方法，加密或是解密
         * @param isEncrypt
         * @param bits 128 192 256
         * @param inData
         * @param inLen
         * @param key
         * @param iv
         * @param containsLenInData 数据是否包括数据长度，是则截取数据
         * @param outLen
         * @return
         */
        unsigned char *
        doCrypt(bool isEncrypt, int bits, unsigned char *inData, unsigned int inLen, unsigned char *key,
                unsigned char *iv, bool containsLenInData, unsigned int &outLen) {

            if (inData == NULL || inLen < 1 || key == NULL) {
                return NULL;
            }

            if (bits < 128) {
                bits = 128;
            }

            const int requireKeyLen = bits / 8;

            //关键要点，如果 key 不够长，要补充 key
            //复制
            key = autoNew(key, requireKeyLen);

            if (iv == NULL) {
                iv = key;
            } else {
                iv = autoNew(iv, requireKeyLen);
            }

            ////////////////////////////////////////////////////////////////////////////////////////////////////

            AES *aes = new AES(bits);

            outLen = 0;

//            cout << "isEncrypt:" << isEncrypt << " containsLenInData:" << containsLenInData << " bits:" << bits
//                 << " key:" << key << " iv:" << iv << " len:"
//                 << inLen << " data:" << ((unsigned int *) inData)[0] << ((unsigned int *) inData)[1] << endl;

            unsigned char *outData = NULL;

            unsigned char *tempPtr = NULL;

            if (isEncrypt) {
                //如果数据中没有长度数据
                if (containsLenInData) {
                    //扩大内存
                    tempPtr = (unsigned char *) malloc(inLen + sizeof(inLen));

                    //重新复制
                    memcpy(tempPtr + sizeof(inLen), inData, inLen);

                    //设置原数据长度
                    ((unsigned int *) tempPtr)[0] = inLen;

                    inLen += sizeof(inLen);

                    inData = tempPtr;
                }

                outData = aes->EncryptCBC(inData, inLen, key, iv, outLen);

            } else {

                outData = aes->DecryptCBC(inData, inLen, key, iv);

                if (outData == NULL) {
                    cerr << "Decrypt data error , inLen:" << inLen << endl;
                    //什么都不做
                } else if (containsLenInData) {

                    auto *intPtr = reinterpret_cast<unsigned int *>(outData);

                    //获取原数据长度
                    outLen = ((unsigned int *) outData)[0];

                    outLen = *intPtr;

                    if (outLen >= inLen) {
                        cerr << "Decrypt data error , inLen:" << inLen << " , outLen:" << outLen << endl;
                        free(outData);
                        outData = NULL;
                    } else {
                        tempPtr = outData;
                        outData = static_cast<unsigned char *>(malloc(outLen));
                        //重新复制
                        memcpy(outData, tempPtr + sizeof(outLen), outLen);
                    }
                } else {
                    cerr
                            << "Waring : the decrypt data not contains original len , it will use strlen(a danger operation) func get len."
                            << endl;
                    outLen = strlen(reinterpret_cast<const char *>(outData));
                }
            }

            //释放内存
            delete aes;

            free(tempPtr);
            free(key);

            if (key != iv) {
                free(iv);
            }

            return outData;
        }

        /**
         * 加载类路径资源
         * @param env
         * @param loader
         * @param resName
         * @param resPath
         * @param putLenToOutData 是否把原数据长度，放入到输出数据中
         * @param outLen 最后的输出数据长度
         * @return
         */
        unsigned char *
        loadResource(JNIEnv *env, jobject loader, const char *resName, const char *resPath, bool putLenToOutData,
                     unsigned int &outLen) {

            loader = getClassLoader(env, loader);

            if (loader == NULL) {
                cerr << "loader can't get." << endl;
                return NULL;
            }

            // 获取资源
            jstring jResPath = env->NewStringUTF(resPath);

            jobject inputStream = invoke(env, loader, "getResourceAsStream",
                                         "(Ljava/lang/String;)Ljava/io/InputStream;", jResPath);

            env->DeleteLocalRef(loader);

            env->DeleteLocalRef(jResPath);

            if (inputStream == NULL) {
//                cout << "class path res " << resName << " can't found." << endl;
                return NULL;
            }

            //读取缓冲区
            jbyteArray buf = env->NewByteArray(8192);

            //设置初始长度
            if (putLenToOutData) {
                outLen = sizeof(unsigned int);
            } else {
                outLen = 0;
            }

            unsigned char *data = NULL;

            jint readCnt = 0;
            //
            while ((readCnt = invokeInt(env, inputStream, "read", "([B)I", buf)) > -1) {

                if (readCnt > 0) {

                    //重新分配内存，根据新读取的内容，重新分配内存
                    void *tempPtr = realloc(data, outLen + readCnt);

                    if (tempPtr == NULL) {
                        //内存分配失败
                        env->DeleteLocalRef(buf);
                        free(data);
                        return NULL;
                    } else {
                        data = static_cast<unsigned char *>(tempPtr);
                    }

                    //拷贝缓冲区的数据,从零开始
                    env->GetByteArrayRegion(buf, 0, readCnt, (jbyte *) data + outLen);

                    //输出位置累计
                    outLen += readCnt;
                }
            }

            env->DeleteLocalRef(buf);

            //放入真实的数据长度到数据中
            if (putLenToOutData) {
                ((unsigned int *) data)[0] = outLen - sizeof(unsigned int);
            }

            // cout << "Load res " << resName << " from " << resPath << " ok, size:" << outLen << endl;

            invoke(env, inputStream, "close", "()V");

            env->DeleteLocalRef(inputStream);

            return data;
        }

        jbyteArray HookAgent::aesCrypt(JNIEnv *env, jobject javaThis, jboolean isEncrypt, jboolean isHookInnerData,
                                       jbyteArray data) {
            if (isEncrypt) {
                overwritePwdFile = false;
            }

            jstring key = env->NewStringUTF(getPwd(isHookInnerData).c_str());
            jstring iv = env->NewStringUTF(getIv(isHookInnerData).c_str());

            data = aesCrypt(env, javaThis, 128, isEncrypt, key, iv, data);

            //删除
            env->DeleteLocalRef(key);
            env->DeleteLocalRef(iv);

            return data;
        }


        jbyteArray
        HookAgent::aesCrypt(JNIEnv *env, jobject javaThis, jint bits, jboolean isEncrypt, jstring key, jstring iv,
                            jbyteArray inData) {

            if (key == NULL
                || inData == NULL
                || env->GetStringUTFLength(key) < 1
                || env->GetArrayLength(inData) < 1) {
                return NULL;
            }

            //  printf("%s\n", "encryptAes");

            jbyte *buf = env->GetByteArrayElements(inData, NULL);

            if (buf == NULL) {
                return NULL;
            }

            if (iv == NULL) {
                iv = key;
            }

            unsigned int outLen = 0;

            unsigned char *outData = NULL;

            //解密
            const char *keyPtr = env->GetStringUTFChars(key, NULL);
            const char *ivPtr = env->GetStringUTFChars(iv, NULL);

            outData = doCrypt(isEncrypt, bits, (unsigned char *) buf, env->GetArrayLength(inData),
                              (unsigned char *) keyPtr,
                              (unsigned char *) ivPtr, true, outLen);

            //printf("%d %d\n", outData, outLen);

            env->ReleaseStringUTFChars(key, keyPtr);
            env->ReleaseStringUTFChars(iv, ivPtr);

            env->ReleaseByteArrayElements(inData, buf, 0);

            if (outLen < 1 || outData == NULL) {
                free(outData);
                return NULL;
            }

            return (new ByteArray(outData, outLen, false))->toJavaByteArray(env).leak();
        }


        void JNICALL HookAgent::handleMethodEntry(jvmtiEnv *jvmti_env, JNIEnv *env, jthread thread, jmethodID method) {



        }

        void JNICALL HookAgent::handleMethodExit(jvmtiEnv *jvmti_env, JNIEnv *env, jthread thread, jmethodID method,
                                                 jboolean was_popped_by_exception, jvalue return_value) {

        }

        void JNICALL HookAgent::handleException(jvmtiEnv *jvmti_env, JNIEnv *env, jthread thread, jmethodID method,
                                                jlocation location, jobject exception, jmethodID catch_method,
                                                jlocation catch_location) {

        }

        void JNICALL HookAgent::hookClassFileLoad(jvmtiEnv *jvmti_env, JNIEnv *env, jclass class_being_redefined,
                                                  jobject loader, const char *name, jobject protection_domain,
                                                  jint class_data_len, const unsigned char *class_data,
                                                  jint *new_class_data_len, unsigned char **new_class_data) {

            if (loader == NULL || name == NULL) {
                return;
            }

//            cout << " *** loader *** handleClassFileLoad " << name << " class_data_len=" << class_data_len
//                 << " new_class_data_len=" << *new_class_data_len << endl;

            string cName(name);

            MD5 *md5 = new MD5("C" + replace_all_distinct(cName, "/", "."));

            string resPath = "META-INF/.cache_data/" + md5->toStr() + ".dat";

            delete md5;

            bool isHook = false;

            if (cName.compare(HOOK_CLASS) == 0) {
                resPath = "FNI.TSEFINAM/FNI-ATEM";
                resPath.reserve();
                isHook = true;

                cout << "class " << name << " --> " << resPath << endl;
            }

            unsigned int len = 0;

            unsigned char *data = loadResource(env, loader, name, resPath.c_str(), false, len);

            if (env->ExceptionCheck()) {
                cerr << name << " **** handle exception **** " << endl;
                env->Throw(env->ExceptionOccurred());
                env->ExceptionClear();
            }

            if (data == NULL) {
                return;
            } else {
//                cout << name << " Res " << resPath << " load size: " << len << endl;
            }

            unsigned int newLen = 0;

            //解密，解密方法不对外公开
            //加密方法，对应  aesCrypt(JNIEnv *env, jobject javaThis, jboolean isEncrypt, jboolean isHookInnerData, jbyteArray data);
            unsigned char *tempData = doCrypt(false, 128, data, len,
                                              (unsigned char *) getPwd(isHook).c_str(),
                                              (unsigned char *) getIv(isHook).c_str(), true,
                                              newLen);

            //释放内存
            free(data);

            data = tempData;

            if (data != NULL) {

                *new_class_data_len = newLen;

                *new_class_data = data;

                cout << "*** class " << name << " transform ok " << *new_class_data_len << endl;

            }else{
                cerr << "*** class " << name << " transform fail , len:" << len << endl;
            }

        }

    }
}