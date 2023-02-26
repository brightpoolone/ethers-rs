use super::common::JsonRpcError;
use crate::{provider::ProviderError, JsonRpcClient};
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use wasm_bindgen::{prelude::*, closure::Closure, JsValue};
use gloo_utils::format::JsValueSerdeExt;

#[wasm_bindgen]
pub struct Request {
    method: String,
    params: JsValue
}

#[wasm_bindgen]
impl Request {

    pub fn new(method: String, params: JsValue) -> Request {
        Request { method, params }
    }

    #[wasm_bindgen(getter)]
    pub fn method(&self) -> String {
        self.method.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn params(&self) -> JsValue {
        self.params.clone()
    }
}

#[derive(Debug, Clone)]
// All attributes this library needs is thread unsafe.
// But wasm itself is a single threaded... something.
// To avoid problems with Send and Sync, all these parameters are
// fetched whenever it is needed
pub struct Eip1193 {}

#[derive(Error, Debug)]
/// Error thrown when sending an HTTP request
pub enum Eip1193Error {
    /// Thrown if the request failed
    #[error("JsValue error")]
    JsValueError(String),

    /// Thrown if no window.ethereum is found in DOM
    #[error("No ethereum found")]
    JsNoEthereum,

    #[error("Cannot parse ethereum response")]
    JsParseError,

    #[error(transparent)]
    /// Thrown if the response could not be parsed
    JsonRpcError(#[from] JsonRpcError),

    #[error(transparent)]
    /// Serde JSON Error
    SerdeJson (#[from] serde_json::Error),
}

#[wasm_bindgen(inline_js = "export function get_provider_js() {return window.ethereum}")]
extern "C" {
    #[wasm_bindgen(catch)]
    fn get_provider_js() -> Result<Option<Ethereum>, JsValue>;
}

#[wasm_bindgen]
extern "C" {
    #[derive(Clone, Debug)]
    /// An EIP-1193 provider object. Available by convention at `window.ethereum`
    pub type Ethereum;

    #[wasm_bindgen(catch, method)]
    async fn request(_: &Ethereum, args: Request) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method)]
    fn on(_: &Ethereum, eventName: &str, listener: &Closure<dyn FnMut(JsValue)>);

    #[wasm_bindgen(method, js_name = "removeListener")]
    fn removeListener(_: &Ethereum, eventName: &str, listener: &Closure<dyn FnMut(JsValue)>);
}

impl Ethereum {
    pub fn default() -> Result<Self, Eip1193Error> {
        if let Ok(Some(eth)) = get_provider_js() {
            return Ok(eth);
        } else {
            return Err(Eip1193Error::JsNoEthereum);
        }
    }
}

impl From<Eip1193Error> for ProviderError {
    fn from(src: Eip1193Error) -> Self {
        match src {
            Eip1193Error::JsValueError(s) => ProviderError::CustomError(s),
            _ => ProviderError::JsonRpcClientError(Box::new(src)),
        }
    }
}

impl From<JsValue> for Eip1193Error {
    fn from(src: JsValue) -> Self {
        Eip1193Error::JsValueError(format!("{:?}", src))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl JsonRpcClient for Eip1193 {
    type Error = Eip1193Error;

    /// Sends the request via `window.ethereum` in Js
    async fn request<T: Serialize + Send + Sync, R: DeserializeOwned>(
        &self,
        method: &str,
        params: T,
    ) -> Result<R, Eip1193Error> {

        let ethereum = Ethereum::default()?;
        let t_params = JsValue::from_serde(&params)?;
        let js_params = if t_params.is_null() { js_sys::Array::new().into() } else { t_params };
        let payload = Request::new(method.to_string(), js_params.clone());
        

        match ethereum.request(payload).await {
            Ok(r) => Ok(r.into_serde().unwrap()),
            Err(e) => Err(e.into())
        }
    }
}

impl Eip1193 {

    pub fn is_available() -> bool {
        if Ethereum::default().is_ok() {
            return true;
        }
        false
    }

    pub fn new() -> Self {
        Eip1193 {}
    }

    pub fn on(self, event: &str, callback: Box<dyn FnMut(JsValue)>) -> Result<(), Eip1193Error>{
        let ethereum = Ethereum::default()?;
        let closure = Closure::wrap(callback);
        ethereum.on(event, &closure);
        closure.forget();
        Ok(())
    }

}

