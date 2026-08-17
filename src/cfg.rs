macro_rules! cfg_feature {
    (
        #![$meta:meta]
        $($item:item)*
    ) => {
        $(
            #[cfg($meta)]
            #[cfg_attr(docsrs, doc(cfg($meta)))]
            $item
        )*
    }
}

macro_rules! cfg_proto {
    ($($item:item)*) => {
        cfg_feature! {
            #![all(
                any(
                    feature = "http1",
                    feature = "http2",
                    all(feature = "http3", hyper_unstable_quic),
                ),
                any(feature = "client", feature = "server"),
            )]
            $($item)*
        }
    }
}

// HTTP/3 is unstable: it needs the `http3` feature *and* the
// `hyper_unstable_quic` cfg, the same way the C API needs `hyper_unstable_ffi`.
#[allow(unused_macros)]
macro_rules! cfg_http3 {
    ($($item:item)*) => {
        cfg_feature! {
            #![all(feature = "http3", hyper_unstable_quic)]
            $($item)*
        }
    }
}

cfg_proto! {
    #[allow(unused_macros)]
    macro_rules! cfg_client {
        ($($item:item)*) => {
            cfg_feature! {
                #![feature = "client"]
                $($item)*
            }
        }
    }

    #[allow(unused_macros)]
    macro_rules! cfg_server {
        ($($item:item)*) => {
            cfg_feature! {
                #![feature = "server"]
                $($item)*
            }
        }
    }
}
