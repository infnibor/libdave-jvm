#include "jni_utils.h"
#include "moe_kyokobot_libdave_natives_DaveNativeBindings.h"
#include <bytes/bytes.h>
#include <dave.h>
#include <dave_interfaces.h>

using namespace kyoko::libdave;
using namespace discord::dave;

JNIEXPORT jbyteArray JNICALL
Java_moe_kyokobot_libdave_natives_DaveNativeBindings_daveKeyRatchetGetEncryptionKey(
    JNIEnv *env, jobject clazz, jlong handle, jint keyGeneration) {
  auto keyRatchet = reinterpret_cast<IKeyRatchet *>(handle);
  auto key = keyRatchet->GetKey(static_cast<KeyGeneration>(keyGeneration));
  return toByteArray(env, key.as_vec());
}

JNIEXPORT void JNICALL
Java_moe_kyokobot_libdave_natives_DaveNativeBindings_daveKeyRatchetDeleteKey(
    JNIEnv *env, jobject clazz, jlong handle, jint keyGeneration) {
  auto keyRatchet = reinterpret_cast<IKeyRatchet *>(handle);
  keyRatchet->DeleteKey(static_cast<KeyGeneration>(keyGeneration));
}

JNIEXPORT void JNICALL
Java_moe_kyokobot_libdave_natives_DaveNativeBindings_daveKeyRatchetDestroy(
    JNIEnv *env, jobject clazz, jlong handle) {
  auto keyRatchet = reinterpret_cast<IKeyRatchet *>(handle);
  delete keyRatchet;
}
