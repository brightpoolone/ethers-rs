use super::common::JsonRpcError;
use crate::{provider::ProviderError, JsonRpcClient};
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize, Deserialize};
use thiserror::Error;
use wasm_bindgen::{prelude::*, closure::Closure, JsValue};
use gloo_utils::format::JsValueSerdeExt;

#[derive(Serialize, Deserialize)]
pub struct RequestMethod {
    method: String
}

#[wasm_bindgen]
struct RequestArguments {
    method: String,
    params: js_sys::Array,
}

#[wasm_bindgen]
impl RequestArguments {
    #[wasm_bindgen(getter)]
    pub fn method(&self) -> String {
        self.method.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn params(&self) -> js_sys::Array {
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
    async fn request(_: &Ethereum, args: RequestArguments) -> Result<JsValue, JsValue>;

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
        Eip1193Error::JsValueError(src.into_serde::<String>().unwrap())
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
        let params = JsValue::from_serde(&params)?;
        let js_params = if params.is_array() { js_sys::Array::from(&params) } else { js_sys::Array::new() };
        let result = ethereum.request(RequestArguments { method: method.to_string(), params: js_params}).await?;
        
        if let Ok(response) = result.into_serde() {
            Ok(response)
        } else {
            Err(Eip1193Error::JsParseError)
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
        ethereum.on(event, &Closure::wrap(callback));
        Ok(())
    }

}

