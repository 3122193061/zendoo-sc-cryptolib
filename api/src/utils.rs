use super::*;

macro_rules! log {
    ($msg: expr) => {{
        eprintln!("[{}:{}.{}] {:?}", file!(), line!(), column!(), $msg)
    }};
}

pub(crate) fn read_raw_pointer<'a, T>(env: &JNIEnv, input: *const T) -> &'a T {
    if input.is_null() {
        throw_and_exit!(
            env,
            "java/lang/NullPointerException",
            "Received null pointer"
        );
    }
    unsafe { &*input }
}

pub(crate) fn read_mut_raw_pointer<'a, T>(env: &JNIEnv, input: *mut T) -> &'a mut T {
    if input.is_null() {
        throw_and_exit!(
            env,
            "java/lang/NullPointerException",
            "Received null pointer"
        );
    }
    unsafe { &mut *input }
}

pub(crate) fn read_nullable_raw_pointer<'a, T>(input: *const T) -> Option<&'a T> {
    unsafe { input.as_ref() }
}

pub(crate) fn serialize_from_raw_pointer<T: CanonicalSerialize>(
    _env: &JNIEnv,
    to_write: *const T,
    compressed: Option<bool>,
) -> Vec<u8> {
    serialize_to_buffer(read_raw_pointer(&_env, to_write), compressed)
        .unwrap_or_else(|_| panic!("unable to write {} to buffer", type_name::<T>()))
}

pub(crate) fn return_jobject<'a, T: Sized>(
    _env: &'a JNIEnv,
    obj: T,
    class_path: &str,
) -> JObject<'a> {
    //Return field element
    let obj_ptr: jlong = Box::into_raw(Box::new(obj)) as i64;

    let obj_class = _env
        .find_class(class_path)
        .expect("Should be able to find class");

    _env.new_object(obj_class, "(J)V", &[JValue::Long(obj_ptr)])
        .expect("Should be able to create new jobject")
}

pub(crate) fn return_field_element(_env: &JNIEnv, fe: FieldElement) -> jobject {
    return_jobject(_env, fe, "com/horizen/librustsidechains/FieldElement").into_inner()
}

pub(crate) fn deserialize_to_jobject<T: CanonicalDeserialize + SemanticallyValid>(
    _env: &JNIEnv,
    obj_bytes: jbyteArray,
    checked: Option<jboolean>, // Can be none for types with trivial checks or without themn
    compressed: Option<jboolean>, // Can be none for uncompressable types
    class_path: &str,
) -> jobject {
    let obj_bytes = _env
        .convert_byte_array(obj_bytes)
        .expect("Cannot read bytes.");

    let obj = deserialize_from_buffer::<T>(
        obj_bytes.as_slice(),
        checked.map(|jni_bool| jni_bool == JNI_TRUE),
        compressed.map(|jni_bool| jni_bool == JNI_TRUE),
    );

    match obj {
        Ok(obj) => *return_jobject(&_env, obj, class_path),
        Err(e) => {
            log!(format!(
                "Error while deserializing {:?}: {:?}",
                class_path, e
            ));
            std::ptr::null::<jobject>() as jobject
        }
    }
}

pub(crate) fn serialize_from_jobject<T: CanonicalSerialize>(
    _env: &JNIEnv,
    obj: JObject,
    ptr_name: &str,
    compressed: Option<jboolean>, // Can be none for uncompressable types
) -> jbyteArray {
    let pointer = _env
        .get_field(obj, ptr_name, "J")
        .expect("Cannot get object raw pointer.");

    let obj_bytes = serialize_from_raw_pointer(
        _env,
        pointer.j().unwrap() as *const T,
        compressed.map(|jni_bool| jni_bool == JNI_TRUE),
    );

    _env.byte_array_from_slice(obj_bytes.as_slice())
        .expect("Cannot write object.")
}

pub(crate) fn parse_jbyte_array_to_vec(
    _env: &JNIEnv,
    java_byte_array: &jbyteArray,
    length: usize,
) -> Vec<u8> {
    let vec = _env
        .convert_byte_array(*java_byte_array)
        .expect("Should be able to convert to Rust array");

    if vec.len() != length {
        panic!(
            "Retrieved array size {} expected to be {}.",
            vec.len(),
            length
        );
    }

    vec
}

pub(crate) fn get_byte_array(_env: &JNIEnv, java_byte_array: &jbyteArray, buffer: &mut [u8]) {
    let vec = _env
        .convert_byte_array(*java_byte_array)
        .expect("Should be able to convert to Rust array");

    for (pos, e) in vec.iter().enumerate() {
        buffer[pos] = *e;
    }
}

fn parse_jbyte_array_from_jobject(_env: &JNIEnv, obj: JObject, name: &str) -> jbyteArray {
    _env.get_field(obj, name, "[B")
        .unwrap_or_else(|_| panic!("Should be able to read {} field", name))
        .l()
        .unwrap()
        .cast()
}

#[allow(unused)]
pub(crate) fn parse_byte_array_from_jobject(_env: &JNIEnv, obj: JObject, name: &str) -> Vec<u8> {
    _env.convert_byte_array(parse_jbyte_array_from_jobject(_env, obj, name))
        .unwrap()
}

pub(crate) fn parse_fixed_size_byte_array_from_jobject<const N: usize>(
    _env: &JNIEnv,
    obj: JObject,
    name: &str,
) -> [u8; N] {
    let j_bytes = parse_jbyte_array_from_jobject(_env, obj, name);
    parse_jbyte_array_to_vec(_env, &j_bytes, N)
        .try_into()
        .unwrap()
}

#[allow(unused)]
pub(crate) fn parse_fixed_size_bits_from_jbytearray_in_jobject<const N: usize>(
    _env: &JNIEnv,
    obj: JObject,
    name: &str,
) -> [bool; N] {
    let j_bytes = parse_jbyte_array_from_jobject(_env, obj, name);
    let len = (N as f32 / 8f32).ceil() as usize;
    let fixed_bytes = parse_jbyte_array_to_vec(_env, &j_bytes, len);
    bytes_to_bits(&fixed_bytes)[..N].try_into().unwrap()
}

pub(crate) fn parse_long_from_jobject(_env: &JNIEnv, obj: JObject, name: &str) -> u64 {
    _env.get_field(obj, name, "J")
        .unwrap_or_else(|_| panic!("Should be able to read {} field", name))
        .j()
        .unwrap() as u64
}

pub(crate) fn parse_int_from_jobject(_env: &JNIEnv, obj: JObject, name: &str) -> u32 {
    _env.get_field(obj, name, "I")
        .unwrap_or_else(|_| panic!("Should be able to read {} field", name))
        .i()
        .unwrap() as u32
}

pub(crate) fn parse_field_element_from_jobject<'a>(
    _env: &JNIEnv,
    obj: JObject,
    name: &str,
) -> &'a FieldElement {
    let field_object = _env
        .get_field(obj, name, "Lcom/horizen/librustsidechains/FieldElement;")
        .unwrap_or_else(|_| panic!("Should be able to get {} FieldElement", name))
        .l()
        .unwrap();

    let f = _env
        .get_field(field_object, "fieldElementPointer", "J")
        .expect("Should be able to get field fieldElementPointer");

    read_raw_pointer(&_env, f.j().unwrap() as *const FieldElement)
}

pub(crate) fn parse_merkle_path_from_jobject<'a>(
    _env: &JNIEnv,
    obj: JObject,
    name: &str,
) -> &'a GingerMHTPath {
    let path_obj = _env
        .get_field(obj, name, "Lcom/horizen/merkletreenative/MerklePath;")
        .expect("Should be able to get MerklePath field")
        .l()
        .unwrap();

    let t = _env
        .get_field(path_obj, "merklePathPointer", "J")
        .expect("Should be able to get field merklePathPointer");

    read_raw_pointer(&_env, t.j().unwrap() as *const GingerMHTPath)
}

pub(crate) fn parse_joption_from_jobject<'a>(
    _env: &'a JNIEnv,
    obj: JObject<'a>,
    opt_name: &str,
) -> Option<JObject<'a>> {
    // Parse Optional object
    let opt_object = _env
        .get_field(obj, opt_name, "Ljava/util/Optional;")
        .unwrap_or_else(|_| panic!("Should be able to get {} Optional", opt_name))
        .l()
        .unwrap();

    // Cast it to Rust option
    cast_joption_to_rust_option(_env, opt_object)
}

pub(crate) fn cast_joption_to_rust_option<'a>(
    _env: &'a JNIEnv,
    opt_object: JObject<'a>,
) -> Option<JObject<'a>> {
    if !_env
        .call_method(opt_object, "isPresent", "()Z", &[])
        .expect("Should be able to call isPresent method on Optional object")
        .z()
        .unwrap()
    {
        None
    } else {
        Some(
            _env.call_method(opt_object, "get", "()Ljava/lang/Object;", &[])
                .expect("Should be able to unwrap a non empty Optional")
                .l()
                .unwrap(),
        )
    }
}

pub(crate) fn parse_jobject_array_from_jobject(
    _env: &JNIEnv,
    obj: JObject,
    field_name: &str,
    list_obj_name: &str,
) -> jobjectArray {
    _env.get_field(obj, field_name, format!("[L{};", list_obj_name).as_str())
        .unwrap_or_else(|_| panic!("Should be able to get {}", field_name))
        .l()
        .unwrap()
        .cast()
}
