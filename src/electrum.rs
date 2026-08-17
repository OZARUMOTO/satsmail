// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ELECTRUM — zero-dependency Electrum JSON-RPC client over plain TCP.
//
// Talks to the box's bwt instance (127.0.0.1:50001) so the SATSMAIL inbox can
// show a LIVE view of the wallet: balance via `blockchain.scripthash.listunspent`,
// history via `blockchain.scripthash.get_history`, and per-tx net flow via
// `blockchain.transaction.get` (verbose). Broadcasting a signed transaction
// uses `blockchain.transaction.broadcast`.
//
// The Electrum "scripthash" is the byte-reversed SHA256 of a script_pubkey.
//
// HOSTED-NOTE: the Passport Prime device itself is BLE-only (quantum-link) and
// never opens sockets; this module exists so the hosted simulator can talk to
// the box's bwt directly. On hardware the companion fronts the same Electrum
// endpoint over quantum-link.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use ngwallet::bdk_wallet::bitcoin::hashes::{sha256, Hash};

/// One unspent output as reported by `blockchain.scripthash.listunspent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectrumUtxo {
    /// Transaction id in DISPLAY (reverse) byte order.
    pub tx_hash: String,
    pub tx_pos: u32,
    pub value_sats: u64,
    pub height: i64,
}

/// One entry from `blockchain.scripthash.get_history`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectrumHistoryEntry {
    /// Transaction id in display byte order.
    pub tx_hash: String,
    /// Confirmation height; 0 when still in the mempool.
    pub height: i64,
}

/// Verbose transaction data from `blockchain.transaction.get` (verbose=true).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectrumTx {
    pub txid: String,
    /// Confirmation count; 0 when unconfirmed.
    pub confirmations: i64,
    /// Unix seconds the block was mined (0 when unknown/unconfirmed).
    pub block_time: i64,
    /// (value_sats, script_hex) of every input's prevout.
    pub inputs: Vec<(u64, String)>,
    /// (value_sats, script_hex) of every output.
    pub outputs: Vec<(u64, String)>,
}

#[derive(Debug)]
pub enum ElectrumError {
    Io(String),
    Rpc(String),
    BadResponse(String),
}

impl core::fmt::Display for ElectrumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "electrum io: {e}"),
            Self::Rpc(e) => write!(f, "electrum rpc error: {e}"),
            Self::BadResponse(e) => write!(f, "electrum bad response: {e}"),
        }
    }
}

impl std::error::Error for ElectrumError {}

/// Electrum "scripthash": SHA256(scriptPubKey) with the digest byte-reversed,
/// hex-encoded. The lookup key for all `blockchain.scripthash.*` methods.
pub fn scripthash_hex(script: &[u8]) -> String {
    let digest = sha256::Hash::hash(script).to_byte_array();
    let mut rev = digest;
    rev.reverse();
    hex::encode(rev)
}

/// Entry point for every Electrum call. On the real device (keyos) the Prime
/// has no sockets at all — the kernel denies the TCP connect syscall and the
/// SDK's send machinery turns that denial into a hard abort (the exact crash
/// class QXXX hit before its bridge guards landed). Never touch the socket on
/// device builds: surface a clean offline error instead, and the inbox shows
/// "electrum: offline" while everything else (receive address, PSBT scan,
/// sign, QR export) keeps working.
#[cfg(keyos)]
fn rpc_call(
    _host: &str,
    _port: u16,
    _method: &str,
    _params: &[String],
) -> Result<serde_json::Value, ElectrumError> {
    Err(ElectrumError::Io(
        "electrum: offline — device has no network; refresh via QR sync".into(),
    ))
}

#[cfg(not(keyos))]
fn rpc_call(
    host: &str,
    port: u16,
    method: &str,
    params: &[String],
) -> Result<serde_json::Value, ElectrumError> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| ElectrumError::Io(e.to_string()))?
        .next()
        .ok_or_else(|| ElectrumError::Io("no address resolved".into()))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| ElectrumError::Io(e.to_string()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| ElectrumError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| ElectrumError::Io(e.to_string()))?;

    let params_json =
        serde_json::to_string(params).map_err(|e| ElectrumError::BadResponse(format!("params encode: {e}")))?;
    let req = format!("{{\"id\":1,\"method\":\"{method}\",\"params\":{params_json}}}\n");
    stream
        .write_all(req.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|e| ElectrumError::Io(e.to_string()))?;

    let body = read_response(&mut stream)?;
    let value: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| ElectrumError::BadResponse(format!("json: {e}")))?;
    if let Some(err) = value.get("error").filter(|e| !e.is_null()) {
        return Err(ElectrumError::Rpc(err.to_string()));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| ElectrumError::BadResponse("missing result".into()))
}

/// `blockchain.scripthash.listunspent` — unspent outputs for a scripthash.
pub fn list_unspent(
    host: &str,
    port: u16,
    scripthash: &str,
) -> Result<Vec<ElectrumUtxo>, ElectrumError> {
    let result = rpc_call(host, port, "blockchain.scripthash.listunspent", &[scripthash.into()])?;
    let result = result
        .as_array()
        .ok_or_else(|| ElectrumError::BadResponse("missing result array".into()))?;

    let mut utxos = Vec::new();
    for u in result {
        utxos.push(ElectrumUtxo {
            tx_hash: u.get("tx_hash").and_then(|h| h.as_str()).unwrap_or("").to_string(),
            tx_pos: u.get("tx_pos").and_then(|p| p.as_u64()).unwrap_or(0) as u32,
            value_sats: u.get("value").and_then(|v| v.as_u64()).unwrap_or(0),
            height: u.get("height").and_then(|h| h.as_i64()).unwrap_or(0),
        });
    }
    Ok(utxos)
}

/// `blockchain.scripthash.get_history` — every tx that touched the scripthash.
pub fn get_history(
    host: &str,
    port: u16,
    scripthash: &str,
) -> Result<Vec<ElectrumHistoryEntry>, ElectrumError> {
    let result = rpc_call(host, port, "blockchain.scripthash.get_history", &[scripthash.into()])?;
    let result = result
        .as_array()
        .ok_or_else(|| ElectrumError::BadResponse("missing result array".into()))?;

    let mut entries = Vec::new();
    for e in result {
        entries.push(ElectrumHistoryEntry {
            tx_hash: e.get("tx_hash").and_then(|h| h.as_str()).unwrap_or("").to_string(),
            height: e.get("height").and_then(|h| h.as_i64()).unwrap_or(0),
        });
    }
    Ok(entries)
}

/// `blockchain.transaction.get` (verbose) with input prevouts, so the app can
/// compute net flow for its own addresses.
pub fn get_tx_verbose(host: &str, port: u16, txid: &str) -> Result<ElectrumTx, ElectrumError> {
    let result = rpc_call(host, port, "blockchain.transaction.get", &[txid.into(), "true".into()])?;
    let obj = result
        .as_object()
        .ok_or_else(|| ElectrumError::BadResponse("tx result not an object".into()))?;

    let mut inputs = Vec::new();
    if let Some(vin) = obj.get("vin").and_then(|v| v.as_array()) {
        for input in vin {
            let prevout = input.get("prevout").and_then(|p| p.as_object());
            let value = prevout.and_then(|p| p.get("value")).and_then(|v| v.as_u64()).unwrap_or(0);
            let script = prevout
                .and_then(|p| p.get("scriptPubKey"))
                .and_then(|s| s.get("hex"))
                .and_then(|h| h.as_str())
                .unwrap_or("")
                .to_string();
            inputs.push((value, script));
        }
    }
    let mut outputs = Vec::new();
    if let Some(vout) = obj.get("vout").and_then(|v| v.as_array()) {
        for output in vout {
            let value = output.get("value").and_then(|v| v.as_u64()).unwrap_or(0);
            let script = output
                .get("scriptPubKey")
                .and_then(|s| s.get("hex"))
                .and_then(|h| h.as_str())
                .unwrap_or("")
                .to_string();
            outputs.push((value, script));
        }
    }

    Ok(ElectrumTx {
        txid: obj.get("txid").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        confirmations: obj.get("confirmations").and_then(|c| c.as_i64()).unwrap_or(0),
        block_time: obj.get("blocktime").and_then(|t| t.as_i64()).unwrap_or(0),
        inputs,
        outputs,
    })
}

/// `blockchain.transaction.broadcast` — push a signed transaction hex to the
/// network. Returns the txid on success.
pub fn broadcast(host: &str, port: u16, tx_hex: &str) -> Result<String, ElectrumError> {
    let result = rpc_call(host, port, "blockchain.transaction.broadcast", &[tx_hex.into()])?;
    result.as_str().map(str::to_string).ok_or_else(|| ElectrumError::BadResponse("no txid".into()))
}

/// Read a JSON-RPC response body, handling both Content-Length framing
/// (electrs/Fulcrum) and bare newline-delimited responses.
fn read_response(stream: &mut TcpStream) -> Result<String, ElectrumError> {
    let mut reader = BufReader::new(stream);
    let mut first = String::new();
    reader.read_line(&mut first).map_err(|e| ElectrumError::Io(e.to_string()))?;

    if first.starts_with("Content-Length:") {
        let n: usize = first
            .trim_start_matches("Content-Length:")
            .trim()
            .parse()
            .map_err(|_| ElectrumError::BadResponse("bad Content-Length".into()))?;
        loop {
            let mut line = String::new();
            let read = reader.read_line(&mut line).map_err(|e| ElectrumError::Io(e.to_string()))?;
            if read == 0 || line.trim().is_empty() {
                break;
            }
        }
        let mut body = vec![0u8; n];
        reader.read_exact(&mut body).map_err(|e| ElectrumError::Io(e.to_string()))?;
        String::from_utf8(body).map_err(|e| ElectrumError::BadResponse(e.to_string()))
    } else {
        Ok(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn canned_server_crlf(body: &'static str) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = String::new();
            let mut reader = BufReader::new(sock.try_clone().unwrap());
            reader.read_line(&mut req).unwrap();
            let framed = format!("Content-Length: {}\r\n\r\n{}", body.len(), body);
            sock.write_all(framed.as_bytes()).unwrap();
        });
        (port, handle)
    }

    #[test]
    fn scripthash_matches_known_answers() {
        let s1 = hex::decode("51201111111111111111111111111111111111111111111111111111111111111111").unwrap();
        assert_eq!(
            scripthash_hex(&s1),
            "994a2bf6fea18f26cf5a88124cfb2d9f993b3717641b9be3b5c2a963a987c9e8"
        );
    }

    #[test]
    fn list_unspent_parses_canned_response() {
        let body = r#"{"id":1,"result":[{"height":840000,"tx_hash":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899","tx_pos":0,"value":5000000}],"error":null}"#;
        let (port, handle) = canned_server_crlf(body);
        let utxos = list_unspent("127.0.0.1", port, "994a2bf6fea18f26cf5a88124cfb2d9f993b3717641b9be3b5c2a963a987c9e8").unwrap();
        handle.join().unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].value_sats, 5_000_000);
    }

    #[test]
    fn get_tx_verbose_parses_prevouts_and_outputs() {
        let body = r#"{"id":1,"result":{"txid":"aa00000000000000000000000000000000000000000000000000000000000000","confirmations":42,"blocktime":1712000000,"vin":[{"txid":"cc","vout":0,"prevout":{"value":9000,"scriptPubKey":{"hex":"0011"}}}],"vout":[{"value":5000,"scriptPubKey":{"hex":"0012"}},{"value":3900,"scriptPubKey":{"hex":"0013"}}]},"error":null}"#;
        let (port, handle) = canned_server_crlf(body);
        let tx = get_tx_verbose("127.0.0.1", port, "aa00").unwrap();
        handle.join().unwrap();
        assert_eq!(tx.confirmations, 42);
        assert_eq!(tx.inputs, vec![(9000, "0011".to_string())]);
        assert_eq!(tx.outputs, vec![(5000, "0012".to_string()), (3900, "0013".to_string())]);
    }

    #[test]
    fn broadcast_returns_txid() {
        let body = r#"{"id":1,"result":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899","error":null}"#;
        let (port, handle) = canned_server_crlf(body);
        let txid = broadcast("127.0.0.1", port, "01000000").unwrap();
        handle.join().unwrap();
        assert_eq!(txid, "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
    }
}
