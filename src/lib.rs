use hex;
use ngx::core;
use ngx::ffi::ngx_http_request_t;
use ngx::ffi::{
    nginx_version, ngx_array_push, ngx_command_t, ngx_conf_t, ngx_http_core_module,
    ngx_http_handler_pt, ngx_http_module_t, ngx_int_t, ngx_module_t, ngx_str_t, ngx_uint_t,
    NGX_CONF_FLAG, NGX_HTTP_LOC_CONF, NGX_HTTP_MODULE, NGX_RS_HTTP_LOC_CONF_OFFSET,
    NGX_RS_MODULE_SIGNATURE,
};
use ngx::http::HTTPStatus;
use ngx::http::MergeConfigError;
use ngx::http_request_handler;
use ngx::{core::Status, http, http::HTTPModule};
use ngx::{ngx_log_debug_http, ngx_null_command, ngx_string};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use std::fs::File;
use std::io::Read;
use std::os::raw::{c_char, c_void};
use std::ptr::addr_of;

struct Module;

impl HTTPModule for Module {
    type MainConf = ();
    type SrvConf = ();
    type LocConf = ModuleConfig;

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        let cmcf = http::ngx_http_conf_get_module_main_conf(cf, &*addr_of!(ngx_http_core_module));

        let h = ngx_array_push(
            &mut (*cmcf).phases[ngx::ffi::ngx_http_phases_NGX_HTTP_CONTENT_PHASE as usize].handlers,
        ) as *mut ngx_http_handler_pt;
        if h.is_null() {
            return core::Status::NGX_ERROR.into();
        }
        *h = Some(sign_passthrough_handler);
        core::Status::NGX_OK.into()
    }
}

#[derive(Debug, Default)]
struct ModuleConfig {
    enable: bool,
}

impl http::Merge for ModuleConfig {
    fn merge(&mut self, prev: &ModuleConfig) -> Result<(), MergeConfigError> {
        if self.enable == false {
            self.enable = prev.enable;
        }
        Ok(())
    }
}

#[no_mangle]
static mut NGX_HTTP_SIGN_PASSTHROUGH_COMMANDS: [ngx_command_t; 2] = [
    ngx_command_t {
        name: ngx_string!("sign_passthrough"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_FLAG) as ngx_uint_t,
        set: Some(ngx_http_sign_passthrough_commands_set_enable),
        conf: NGX_RS_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_null_command!(),
];

#[no_mangle]
static NGX_HTTP_SIGN_PASSTHROUGH_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(Module::preconfiguration),
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: Some(Module::create_main_conf),
    init_main_conf: Some(Module::init_main_conf),
    create_srv_conf: Some(Module::create_srv_conf),
    merge_srv_conf: Some(Module::merge_srv_conf),
    create_loc_conf: Some(Module::create_loc_conf),
    merge_loc_conf: Some(Module::merge_loc_conf),
};

ngx::ngx_modules!(NGX_HTTP_SIGN_PASSTHROUGH_MODULE);

#[no_mangle]
#[used]
pub static mut NGX_HTTP_SIGN_PASSTHROUGH_MODULE: ngx_module_t = ngx_module_t {
    ctx_index: ngx_uint_t::MAX,
    index: ngx_uint_t::MAX,
    name: std::ptr::null_mut(),
    spare0: 0,
    spare1: 0,
    version: nginx_version as ngx_uint_t,
    signature: NGX_RS_MODULE_SIGNATURE.as_ptr() as *const c_char,

    ctx: &NGX_HTTP_SIGN_PASSTHROUGH_MODULE_CTX as *const ngx_http_module_t as *mut c_void,
    commands: unsafe { NGX_HTTP_SIGN_PASSTHROUGH_COMMANDS.as_ptr() as *mut ngx_command_t },
    type_: NGX_HTTP_MODULE as ngx_uint_t,

    init_master: None,
    init_module: None,
    init_process: None,
    init_thread: None,
    exit_thread: None,
    exit_process: None,
    exit_master: None,

    spare_hook0: 0,
    spare_hook1: 0,
    spare_hook2: 0,
    spare_hook3: 0,
    spare_hook4: 0,
    spare_hook5: 0,
    spare_hook6: 0,
    spare_hook7: 0,
};

#[no_mangle]
extern "C" fn ngx_http_sign_passthrough_commands_set_enable(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let val = (*args.add(1)).to_str();

        conf.enable = false;

        if val.eq_ignore_ascii_case("on") {
            conf.enable = true;
        } else if val.eq_ignore_ascii_case("off") {
            conf.enable = false;
        }
    }

    std::ptr::null_mut()
}

http_request_handler!(sign_passthrough_handler, |request: &mut http::Request| {
    ngx_log_debug_http!(request, "Sign passthrough handler called");
    let conf = unsafe {
        request.get_module_loc_conf::<ModuleConfig>(&*addr_of!(NGX_HTTP_SIGN_PASSTHROUGH_MODULE))
    };
    let conf = conf.expect("module config is none");
    ngx_log_debug_http!(request, "Module config: {:?}", conf);

    // FIXME: I don't why but this check is not working because the value of conf.enable is always false (not important for now)
    //if !conf.enable {
    //    ngx_log_debug_http!(request, "Module is disabled");
    //    return core::Status::NGX_DECLINED;
    //}

    let mut file = match File::open("/etc/nginx/certs/rsa_private_key.pem") {
        Ok(f) => f,
        Err(_) => {
            ngx_log_debug_http!(request, "Failed to open RSA private key file");
            return HTTPStatus::INTERNAL_SERVER_ERROR.into();
        }
    };

    let mut pem_data = Vec::new();
    if let Err(e) = file.read_to_end(&mut pem_data) {
        ngx_log_debug_http!(request, "Failed to read RSA private key file: {:?}", e);
        return HTTPStatus::INTERNAL_SERVER_ERROR.into();
    }

    let rsa = match Rsa::private_key_from_pem(&pem_data) {
        Ok(key) => key,
        Err(_) => {
            ngx_log_debug_http!(request, "Failed to parse RSA private key");
            return HTTPStatus::INTERNAL_SERVER_ERROR.into();
        }
    };

    let pkey = match PKey::from_rsa(rsa) {
        Ok(key) => key,
        Err(_) => {
            ngx_log_debug_http!(request, "Failed to create PKey from RSA");
            return HTTPStatus::INTERNAL_SERVER_ERROR.into();
        }
    };

    let mut signer = match Signer::new(MessageDigest::sha256(), &pkey) {
        Ok(s) => s,
        Err(_) => {
            ngx_log_debug_http!(request, "Failed to create signer");
            return HTTPStatus::INTERNAL_SERVER_ERROR.into();
        }
    };

    let body = "placeholder".as_bytes();

    if let Err(_) = signer.update(body) {
        ngx_log_debug_http!(request, "Failed to update signer with body");
        return HTTPStatus::INTERNAL_SERVER_ERROR.into();
    }

    let signature = match signer.sign_to_vec() {
        Ok(sig) => sig,
        Err(_) => {
            ngx_log_debug_http!(request, "Failed to sign body");
            return HTTPStatus::INTERNAL_SERVER_ERROR.into();
        }
    };

    let hex_signature = hex::encode(signature);

    request.add_header_out("X-Signed-Checksum", &hex_signature);

    ngx_log_debug_http!(request, "Response body signed");

    core::Status::NGX_OK
});
