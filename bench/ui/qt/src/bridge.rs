use crate::bridge_impl::BenchBridgeRust;

#[cxx_qt::bridge(namespace = "yonik_bench")]
pub mod ffi {
    #[namespace = ""]
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    unsafe extern "C++" {
        include!("application.h");
        fn run_application() -> i32;
        fn rendered_frames() -> u64;
        fn request_probe(nonce: u64);
        fn request_frame(token: i32);
        fn exit_application();
        fn resume_for_show();
    }

    impl cxx_qt::Threading for BenchBridge {}

    extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qproperty(QString, snapshot_json)]
        #[qproperty(QString, control_json)]
        type BenchBridge = super::BenchBridgeRust;

        #[qinvokable]
        fn initialize(self: Pin<&mut BenchBridge>);
        #[qinvokable]
        fn dispatch(self: Pin<&mut BenchBridge>, request: QString);
        #[qinvokable]
        fn request_frame(self: Pin<&mut BenchBridge>, token: i32);
        #[qinvokable]
        fn finish_probe(
            self: Pin<&mut BenchBridge>,
            nonce: QString,
            created: i32,
            live: i32,
            visible: i32,
            scroll: i32,
        );
        #[qinvokable]
        fn finish(
            self: Pin<&mut BenchBridge>,
            event: QString,
            created: i32,
            live: i32,
            visible: i32,
            scroll: i32,
        );
    }
}
