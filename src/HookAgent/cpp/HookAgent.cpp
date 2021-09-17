
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

            cout << "options:" + pwdFileName << endl;

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

            if (pwd.empty() || pwd.find_first_of(INVALID_PWD_PREFIX) != string::npos) {
                pwd ="";
                cout << "pwd file " << current_working_directory() << "/" << pwdFileName << " not exist or empty."
                     << endl;
            } else {
                //覆盖密码文件内容
                overwriteFile(pwdFileName, string(INVALID_PWD_PREFIX) + "#pwd already read.");
            }

            return pwd;
        }

        jclass HookAgent::getHookClass(jvmtiEnv *jvmti_env, JNIEnv *env) {

            if (hookClass != NULL) {
                return hookClass;
            }

            jclass helperClass = env->FindClass(HELPER_CLASS);

            if (helperClass == NULL) {
                cout << "class " << HELPER_CLASS << " not found." << endl;
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

            //读取文件内容
            jbyteArray data = (jbyteArray) env->CallStaticObjectMethod(helperClass,
                                                                       env->GetStaticMethodID(helperClass,
                                                                                              "loadResource",
                                                                                              "(Ljava/lang/String;)[B"),
                                                                       (new JavaString(tempRes))->toJavaString(
                                                                               env).get());

            if (data == NULL) {
                cerr << "res load fail." << endl;
                return NULL;
            }

            //解密 HOOK 类
            data = aesCrypt(env, NULL, JNI_FALSE, JNI_TRUE, data);

            if (data == NULL || env->GetArrayLength(data) < 1) {
                cerr << "res decode fail." << endl;
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
                cerr << "define class error" << endl;
            }

            //释放内存
            env->ReleaseByteArrayElements(data, buf, 0);

            return hookClass;
        }

        jbyteArray HookAgent::aesCrypt(JNIEnv *env, jobject javaThis, jboolean isEncrypt, jboolean isHookInnerData,
                                       jbyteArray data) {

            string tempPwd = readPwd();

            if (tempPwd.empty()) {
                return NULL;
            }

            tempPwd += (isHookInnerData) ? "20l%$#@Echo!&*21" : "21Ho2009&*$%#oK";

            return aesCrypt(env, javaThis, 256, isEncrypt, (new JavaString(tempPwd))->toJavaString(env).leak(), NULL,
                            data);

        }


        jbyteArray
        HookAgent::aesCrypt(JNIEnv *env, jobject javaThis, jint bits, jboolean isEncrypt, jstring key, jstring iv,
                            jbyteArray data) {

            if (key == NULL
                || data == NULL
                || env->GetStringUTFLength(key) < 1
                || env->GetArrayLength(data) < 1) {
                return NULL;
            }

            //  printf("%s\n", "encryptAes");

            jbyte *buf = env->GetByteArrayElements(data, NULL);

            if (buf == NULL) {
                return NULL;
            }

            if (iv == NULL) {
                iv = key;
            }

            AES *aes = new AES(bits);

            unsigned int inLen = env->GetArrayLength(data);
            unsigned int outLen = 0;

            unsigned char *outData = NULL;

            unsigned char *keyP = (unsigned char *) (new JavaString(env, key))->get().c_str();;
            unsigned char *ivP = (unsigned char *) (new JavaString(env, iv))->get().c_str();;

            if (isEncrypt) {
                outData = aes->EncryptCBC(reinterpret_cast<unsigned char *>(buf), inLen, keyP, ivP, outLen);
            } else {
                outData = aes->DecryptCBC(reinterpret_cast<unsigned char *>(buf), inLen, keyP, ivP);
                //获取长度
                outLen = strlen(reinterpret_cast<const char *>(outData));
            }

            //printf("%d %d\n", outData, outLen);

            //释放数组
            env->ReleaseByteArrayElements(data, buf, 0);

            if (outLen < 1 || outData == NULL) {
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

        void JNICALL HookAgent::handleClassFileLoad(jvmtiEnv *jvmti_env, JNIEnv *env, jclass class_being_redefined,
                                                    jobject loader, const char *name, jobject protection_domain,
                                                    jint class_data_len, const unsigned char *class_data,
                                                    jint *new_class_data_len, unsigned char **new_class_data) {

            cout << "handleClassFileLoad " << name << " class_data_len " << class_data_len << endl;

            *new_class_data = NULL;

            *new_class_data_len = 0;

            if (loader == NULL || name == NULL) {
                return;
            }

            if (getHookClass(jvmti_env, env) == NULL) {
                return;
            }

            jboolean envOK = env->CallStaticBooleanMethod(hookClass,
                                                          env->GetStaticMethodID(hookClass,
                                                                                 "isEnvEnable",
                                                                                 "()Z"));

            if (!envOK) {

                cout << "env test fail" << endl;

                return;
            }

            jbyteArray data = static_cast<jbyteArray>(env->CallStaticObjectMethod(hookClass,
                                                                                  env->GetStaticMethodID(hookClass,
                                                                                                         "loadClassData",
                                                                                                         "(Ljava/lang/String;)[B"),
                                                                                  (new JavaString(name))->toJavaString(
                                                                                          env).leak()));
            if (data == NULL) {
                return;
            }

            //解密
            data = aesCrypt(env, NULL, JNI_FALSE, JNI_FALSE, data);

            if (data != NULL) {

                *new_class_data_len = env->GetArrayLength(data);

                *new_class_data = reinterpret_cast<unsigned char *>(env->GetByteArrayElements(data, NULL));

                cout << "handleClassFileLoad " << name << " transform ok " << *new_class_data_len << endl;
            }

        }

    }
}