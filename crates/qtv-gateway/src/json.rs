
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(u64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(n) => out.push_str(&n.to_string()),
            Json::Str(s) => write_string(s, out),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(fields) => {
                out.push('{');
                for (i, (key, value)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Int(n) => Some(*n),
            _ => None,
        }
    }
}

pub fn object(fields: Vec<(&str, Json)>) -> Json {
    Json::Object(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 32 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

const MAX_DEPTH: usize = 64;

pub fn parse(input: &str) -> Result<Json, String> {
    let mut parser = Parser {
        chars: input.chars().collect(),
        pos: 0,
        depth: 0,
    };
    parser.skip_ws();
    let value = parser.value()?;
    parser.skip_ws();
    if parser.pos != parser.chars.len() {
        return Err("trailing characters after the JSON value".to_string());
    }
    Ok(value)
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek() {
            Some('{') => self.nested(Self::object),
            Some('[') => self.nested(Self::array),
            Some('"') => Ok(Json::Str(self.string()?)),
            Some('t') | Some('f') => self.boolean(),
            Some('n') => self.null(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.number(),
            _ => Err("expected a JSON value".to_string()),
        }
    }

    fn nested(&mut self, parse_container: fn(&mut Self) -> Result<Json, String>) -> Result<Json, String> {
        if self.depth >= MAX_DEPTH {
            return Err("the JSON nests deeper than the gateway allows".to_string());
        }
        self.depth += 1;
        let result = parse_container(self);
        self.depth -= 1;
        result
    }

    fn object(&mut self) -> Result<Json, String> {
        self.next();
        let mut fields = Vec::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.next();
            return Ok(Json::Object(fields));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err("expected a string key".to_string());
            }
            let key = self.string()?;
            self.skip_ws();
            if self.next() != Some(':') {
                return Err("expected a colon after a key".to_string());
            }
            let value = self.value()?;
            fields.push((key, value));
            self.skip_ws();
            match self.next() {
                Some(',') => continue,
                Some('}') => break,
                _ => return Err("expected a comma or a closing brace".to_string()),
            }
        }
        Ok(Json::Object(fields))
    }

    fn array(&mut self) -> Result<Json, String> {
        self.next();
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.next();
            return Ok(Json::Array(items));
        }
        loop {
            let value = self.value()?;
            items.push(value);
            self.skip_ws();
            match self.next() {
                Some(',') => continue,
                Some(']') => break,
                _ => return Err("expected a comma or a closing bracket".to_string()),
            }
        }
        Ok(Json::Array(items))
    }

    fn string(&mut self) -> Result<String, String> {
        self.next();
        let mut s = String::new();
        loop {
            match self.next() {
                Some('"') => return Ok(s),
                Some('\\') => match self.next() {
                    Some('"') => s.push('"'),
                    Some('\\') => s.push('\\'),
                    Some('/') => s.push('/'),
                    Some('n') => s.push('\n'),
                    Some('r') => s.push('\r'),
                    Some('t') => s.push('\t'),
                    Some('b') => s.push('\u{0008}'),
                    Some('f') => s.push('\u{000c}'),
                    Some('u') => s.push(self.unicode_escape()?),
                    _ => return Err("bad escape in a string".to_string()),
                },
                Some(c) => s.push(c),
                None => return Err("a string was not closed".to_string()),
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        let mut code = 0u32;
        for _ in 0..4 {
            let digit = self
                .next()
                .and_then(|c| c.to_digit(16))
                .ok_or("bad unicode escape")?;
            code = code * 16 + digit;
        }
        char::from_u32(code).ok_or_else(|| "bad unicode code point".to_string())
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.next();
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.next();
        }
        let text: String = self.chars[start..self.pos].iter().collect();
        text.parse::<u64>()
            .map(Json::Int)
            .map_err(|_| format!("'{text}' is not a whole number the wire accepts"))
    }

    fn boolean(&mut self) -> Result<Json, String> {
        if self.literal("true") {
            Ok(Json::Bool(true))
        } else if self.literal("false") {
            Ok(Json::Bool(false))
        } else {
            Err("expected true or false".to_string())
        }
    }

    fn null(&mut self) -> Result<Json, String> {
        if self.literal("null") {
            Ok(Json::Null)
        } else {
            Err("expected null".to_string())
        }
    }

    fn literal(&mut self, word: &str) -> bool {
        let end = self.pos + word.len();
        if end <= self.chars.len() && self.chars[self.pos..end].iter().collect::<String>() == word {
            self.pos = end;
            true
        } else {
            false
        }
    }
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("hex has an odd length".to_string());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("a nibble is a hex digit"));
        s.push(char::from_digit((b & 15) as u32, 16).expect("a nibble is a hex digit"));
    }
    s
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("'{}' is not a hex digit", c as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field_count(value: &Json) -> usize {
        match value {
            Json::Object(fields) => fields.len(),
            _ => 0,
        }
    }

    #[test]
    fn deeply_nested_json_is_refused_rather_than_overflowing_the_stack() {
        let deep = "[".repeat(200_000);
        let result = parse(&deep);
        assert!(result.is_err(), "deeply nested JSON must be refused");
        assert!(
            result.unwrap_err().contains("nests deeper"),
            "the refusal names the nesting limit"
        );
    }

    #[test]
    fn a_wide_but_shallow_array_still_parses() {
        let wide = format!("[{}]", vec!["1"; 10_000].join(","));
        let value = parse(&wide).expect("a wide flat array parses");
        assert!(matches!(value, Json::Array(items) if items.len() == 10_000));
    }

    #[test]
    fn a_render_round_trips_through_the_parser() {
        let value = object(vec![
            ("chain_id", Json::str("Q-test-net-1")),
            ("height", Json::Int(42)),
            ("balance", Json::str("100000000000")),
            ("ok", Json::Bool(true)),
            ("ids", Json::Array(vec![Json::str("qtx1a"), Json::str("qtx1b")])),
        ]);
        let text = value.render();
        let back = parse(&text).expect("parse");
        assert_eq!(back.get("chain_id").and_then(Json::as_str), Some("Q-test-net-1"));
        assert_eq!(back.get("height").and_then(Json::as_u64), Some(42));
        assert_eq!(field_count(&back), 5);
    }

    #[test]
    fn a_string_with_escapes_round_trips() {
        let value = Json::str("line\none\t\"quoted\"");
        let back = parse(&value.render()).expect("parse");
        assert_eq!(back.as_str(), Some("line\none\t\"quoted\""));
    }

    #[test]
    fn hex_round_trips() {
        let bytes = vec![0u8, 1, 15, 16, 255];
        assert_eq!(from_hex(&to_hex(&bytes)).unwrap(), bytes);
    }
}
