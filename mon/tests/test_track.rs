use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use mon::server::{Command, Response, Server};

#[test]
fn parse_commands() {
    let tree: Command = serde_json::from_str(r#"{"cmd":"tree","pid":1234}"#).unwrap();
    assert_eq!(tree, Command::Tree { pid: 1234 });

    let untrack: Command = serde_json::from_str(r#"{"cmd":"untrack","pid":5678}"#).unwrap();
    assert_eq!(untrack, Command::Untrack { pid: 5678 });

    assert!(serde_json::from_str::<Command>(r#"{"cmd":"track","pid":1}"#).is_err());
}

#[test]
fn serialize_response() {
    let ok = Response::ok("hello");
    let json = serde_json::to_string(&ok).unwrap();
    assert_eq!(json, r#"{"status":"ok","message":"hello"}"#);

    let err = Response::error("something broke");
    let json = serde_json::to_string(&err).unwrap();
    assert_eq!(json, r#"{"status":"error","error":"something broke"}"#);
}

#[test]
fn socket_lifecycle_and_malformed_request() {
    let sock_path = PathBuf::from(format!("/tmp/test_sock_{}.sock", std::process::id()));
    {
        let listener = Server::bind(&sock_path).unwrap();
        assert_eq!(listener.path(), sock_path.as_path());
        assert!(sock_path.exists());

        let mut client = UnixStream::connect(&sock_path).unwrap();
        client.write_all(b"not json\n").unwrap();

        // Accept and respond
        let (mut server_stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(server_stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let resp = match serde_json::from_str::<Command>(line.trim()) {
            Ok(_) => unreachable!(),
            Err(e) => Response::error(format!("invalid command JSON: {e}")),
        };
        let mut out = serde_json::to_vec(&resp).unwrap();
        out.push(b'\n');
        server_stream.write_all(&out).unwrap();

        let mut client_reader = BufReader::new(client);
        let mut resp_line = String::new();
        client_reader.read_line(&mut resp_line).unwrap();
        let resp_obj: Response = serde_json::from_str(resp_line.trim()).unwrap();
        assert!(matches!(resp_obj, Response::Error { .. }));
    }

    // After listener is dropped, socket path should be deleted
    assert!(!sock_path.exists());
}
