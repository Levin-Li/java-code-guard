
#include "HookAgent.h"

#include "SimpleClassFileTransformer.h"

// 注意 jni 和 jvmti agent 的接口 都不允许在名称空间里面

/////////////////////////////// JNI Interface /////////////////////////////////////
ClassRegistry gClasses;

jclass hookClass;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) {

    LOG_INFO("Initializing JNI");
    JNIEnv *env = jniHelpersInitialize(jvm);

    if (env == NULL) {
        return -1;
    }

    gClasses.add(env, new SimpleClassFileTransformer(env));

    printf("%s\n", "JNI_OnLoad");

    LOG_INFO("Initialization complete");
    return JAVA_VERSION;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    printf("%s\n", "JNI_OnUnload");
}

//////////////////////////// jvmit agent ///////////////////////////////////////

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {

    cout << "Agent_OnLoad(" << vm << ")" << endl;

    try {

        HookAgent *agent = new HookAgent();

        agent->init(vm);

        agent->parseOptions(options);

        agent->addCapabilities();

        agent->registerEvents();

    } catch (AgentException &e) {
        cout << "Error when enter HandleMethodEntry: " << e.what() << " [" << e.ErrCode() << "]";
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

        jvmtiEnv *HookAgent::jvmti_env = NULL;
        string HookAgent::pwdFileName = "";
        string HookAgent::pwd = "";
        //密码


        HookAgent::~HookAgent() throw(AgentException) {
            // 必须释放内存，防止内存泄露
        }

        void HookAgent::init(JavaVM *vm) const throw(AgentException) {

            jvmtiEnv *jvmti = NULL;

            jint ret = (vm)->GetEnv(reinterpret_cast<void **>(&jvmti), JVMTI_VERSION); //JVMTI_VERSION

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

            cout << "options:" + pwdFileName;

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

            callbacks.ClassFileLoadHook = &HookAgent::handleClassFileLoad;
            callbacks.Exception = &HookAgent::handleException;

            // 设置回调函数
            checkException(jvmti_env->SetEventCallbacks(&callbacks, static_cast<jint>(sizeof(callbacks))));

            // 开启事件监听
            enableEventNotify(JVMTI_EVENT_METHOD_ENTRY);
            enableEventNotify(JVMTI_EVENT_METHOD_EXIT);
            enableEventNotify(JVMTI_EVENT_CLASS_FILE_LOAD_HOOK);
            enableEventNotify(JVMTI_EVENT_EXCEPTION);
        }


        string HookAgent::readPwd() {

            if (!pwd.empty()) {
                return pwd;
            }

            if (pwdFileName.empty()) {
                pwdFileName = ".java_agent/.pwdFile.txt";
            }

            //静态密码
            //从文件读取动态密码
            pwd = readFile(pwdFileName);

            if (pwd.empty()) {
                cout << "pwd file not exist or empty.";
            } else {
                //覆盖密码文件内容
                writeFile(pwdFileName, "pwd read ok.");
            }

            return pwd;
        }

        jclass HookAgent::getHookClass(jvmtiEnv *jvmti_env, JNIEnv *env) {

            if (hookClass != NULL) {
                return hookClass;
            }

            jclass helperClass = env->FindClass(HELPER_CLASS);

            if (helperClass == NULL) {
                cout << "class " << HELPER_CLASS << " not found.";
                return NULL;
            }

            if (readPwd().empty()) {
                return NULL;
            }

            //故意使用混淆的名字  META-INF/MANIFEST.INF  倒序
            string tempRes = "FNI.TSEFINAM/FNI-ATEM";

            //用于检测文件是否被修改
            // com.levin.commons.plugins.jni.HookAgent_jar_file_hash_sha256 --> sha256哈希值hex字符串翻转
            // 56089cb49222837a65c5bc060a1822e1b35a3ae5307ceb052633c4aee4afddbb --> 字符串翻转  bbddfa4eea4c336250bec7035ea3a53b1e2281a060cb5c56a73822294bc98065
            string hash = "bbddfa4eea4c336250bec7035ea3a53b1e2281a060cb5c56a73822294bc98065";
            //todo 读取 jar 文件进行sha256比对，确认文件没有被修改

            hash.reserve();
            tempRes.reserve();

            //读取文件内容，准备解密
            jbyteArray data = (jbyteArray) env->CallStaticObjectMethod(helperClass,
                                                                       env->GetStaticMethodID(helperClass,
                                                                                              "loadResource",
                                                                                              "(Ljava/lang/String;)[B"),
                                                                       env->NewStringUTF(tempRes.c_str()));

            if (data == NULL) {
                cerr << "res load fail.";
                return NULL;
            }

            //解密
            data = aesCrypt(env, NULL, JNI_FALSE, data);

            if (data == NULL || env->GetArrayLength(data) < 1) {
                cerr << "res decode fail.";
                return NULL;
            }

            jbyte *buf = env->GetByteArrayElements(data, NULL);

            if (buf == NULL) {
                return NULL;
            }

            //定义类
            hookClass = env->DefineClass(HOOK_CLASS,
                                         env->CallStaticObjectMethod(helperClass, env->GetStaticMethodID(helperClass,
                                                                                                         "getCurrentThreadClassLoader",
                                                                                                         "()Ljava/lang/ClassLoader;")),
                                         buf, env->GetArrayLength(data));

            if (hookClass == NULL) {
                cerr << "define class error";
            }

            return hookClass;
        }

        jbyteArray HookAgent::aesCrypt(JNIEnv *env, jobject javaThis, jboolean isEncrypt, jbyteArray data) {

            const string tempPwd = readPwd();

            if (tempPwd.empty()) {
                return NULL;
            }

            JavaString pwd("20l%$#@Echo!&*21" + tempPwd);

            return aesCrypt(env, javaThis, 256, isEncrypt, pwd.toJavaString(env).leak(), data);
        }

        jbyteArray HookAgent::aesCrypt(JNIEnv *env, jobject javaThis, jint bits, jboolean isEncrypt, jstring password,
                                       jbyteArray data) {

            if (password == NULL
                || data == NULL
                || env->GetStringUTFLength(password) < 1
                || env->GetArrayLength(data) < 1) {
                return NULL;
            }

            //  printf("%s\n", "encryptAes");

            jbyte *buf = env->GetByteArrayElements(data, NULL);

            if (buf == NULL) {
                return NULL;
            }

            JavaString pwd(env, password);

            AES *aes = new AES(bits);

            unsigned int outLen = 0;

            unsigned char *outData = NULL;

            if (isEncrypt) {
                outData = aes->EncryptCBC(
                        reinterpret_cast<unsigned char *>(buf),
                        env->GetArrayLength(data),
                        (unsigned char *) pwd.get().c_str(), (unsigned char *) pwd.get().c_str(), outLen);

            } else {

                outData = aes->DecryptCBC(
                        reinterpret_cast<unsigned char *>(buf),
                        env->GetArrayLength(data),
                        (unsigned char *) pwd.get().c_str(), (unsigned char *) pwd.get().c_str());

                //获取长度
                outLen = strlen(reinterpret_cast<const char *>(outData));
            }

            //  printf("%d %d\n", outData, outLen);

            //释放数组
            env->ReleaseByteArrayElements(data, buf, 0);

            if (outLen < 1 || outData == NULL) {
                return NULL;
            }

            ByteArray *result = new ByteArray(outData, outLen, false);

            return result->toJavaByteArray(env).leak();

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

        void JNICALL HookAgent::handleClassFileLoad(jvmtiEnv *jvmti_env, JNIEnv *env, jclass class_being_redefined,
                                                    jobject loader, const char *name, jobject protection_domain,
                                                    jint class_data_len, const unsigned char *class_data,
                                                    jint *new_class_data_len, unsigned char **new_class_data) {

            cout << "handleClassFileLoad " << name << " class_data_len " << class_data_len;

            *new_class_data = NULL;

            *new_class_data_len = 0;

            if (loader == NULL || name == NULL) {
                return;
            }

            if (getHookClass(jvmti_env, env) == NULL) {
                return;
            }

            env->GetStaticMethodID(hookClass, env->GetStaticMethodID(hookClass, "",));

            AES aes(256);

            aes.DecryptCBC()

        }

    }
}