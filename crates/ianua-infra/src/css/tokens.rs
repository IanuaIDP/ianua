//! The tokens of a stylesheet, read as the CSS Syntax Module Level 3
//! tokenizer reads them, so the sanitizer sees the text the way a browser
//! does: comments dropped, escapes decoded, strings and `url(..)` read as
//! one token each however they are written.
//!
//! Only what the sanitizer needs is kept: a string's or a URL's text is
//! never kept, since neither is ever written back.

/// What a decoded escape or a stray NUL stands for when it names no
/// character a stylesheet may hold.
const REPLACEMENT: char = '\u{FFFD}';

/// The most hex digits one escape reads.
const MOST_ESCAPE_DIGITS: u8 = 6;

/// One token of a stylesheet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token {
    /// A name, such as `color` or `red`, its escapes decoded.
    Ident(String),
    /// A name followed by `(`, such as `rgb(`.
    Function(String),
    /// `@` and a name, such as `@import`.
    AtKeyword(String),
    /// `#` and a name, such as `#fff` or `#login`.
    Hash(String),
    /// A quoted string.
    Quoted,
    /// A quoted string broken by a line end.
    BadString,
    /// An unquoted `url(..)`.
    Url,
    /// An unquoted `url(..)` holding what a URL may not.
    BadUrl,
    /// A number as written, its sign included.
    Number(String),
    /// A number and `%`.
    Percentage(String),
    /// A number and a unit, such as `4px`.
    Dimension(String, String),
    /// Spaces, tabs and line ends.
    Whitespace,
    /// Separates a declaration's property from its value.
    Colon,
    /// Ends a declaration within a rule.
    Semicolon,
    /// Separates selectors or list items.
    Comma,
    /// Begins a parenthesized block.
    OpenParen,
    /// Ends a parenthesized block.
    CloseParen,
    /// Begins a block such as an attribute selector.
    OpenSquare,
    /// Ends a block such as an attribute selector.
    CloseSquare,
    /// Begins a rule's declaration block.
    OpenCurly,
    /// Ends a rule's declaration block.
    CloseCurly,
    /// Opens an HTML-style comment recognized by CSS syntax.
    Cdo,
    /// Closes an HTML-style comment recognized by CSS syntax.
    Cdc,
    /// Any other single character.
    Delim(char),
}

/// The tokens of `css`, in order.
pub(crate) fn tokens(css: &str) -> Vec<Token> {
    let mut tokenizer = Tokenizer::new(css);
    std::iter::from_fn(|| tokenizer.next_token()).collect()
}

/// Reads tokens off a stylesheet's characters.
struct Tokenizer {
    chars: Vec<char>,
    at: usize,
}

impl Tokenizer {
    /// A tokenizer at the start of `css`, its line ends and NULs made
    /// plain first, as the standard asks.
    fn new(css: &str) -> Self {
        let plain = css
            .replace("\r\n", "\n")
            .replace(['\r', '\u{c}'], "\n")
            .replace('\0', "\u{FFFD}");
        Self {
            chars: plain.chars().collect(),
            at: 0,
        }
    }

    /// The character `ahead` places past the current one.
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at.saturating_add(ahead)).copied()
    }

    /// The current character, moving past it.
    fn bump(&mut self) -> Option<char> {
        let current = self.peek(0)?;
        self.at = self.at.saturating_add(1);
        Some(current)
    }

    /// Moves past `count` characters.
    fn skip(&mut self, count: usize) {
        self.at = self.at.saturating_add(count);
    }

    /// The next token, or `None` at the end.
    fn next_token(&mut self) -> Option<Token> {
        self.skip_comments();
        let current = self.peek(0)?;
        let token = match current {
            ' ' | '\t' | '\n' => self.whitespace(),
            '"' | '\'' => self.string(current),
            '#' => self.hash(),
            '(' => self.single(Token::OpenParen),
            ')' => self.single(Token::CloseParen),
            '[' => self.single(Token::OpenSquare),
            ']' => self.single(Token::CloseSquare),
            '{' => self.single(Token::OpenCurly),
            '}' => self.single(Token::CloseCurly),
            ',' => self.single(Token::Comma),
            ':' => self.single(Token::Colon),
            ';' => self.single(Token::Semicolon),
            '+' | '.' if self.starts_number() => self.numeric(),
            '-' => self.minus(),
            '<' => self.less_than(),
            '@' => self.at_keyword(),
            '\\' if self.starts_ident() => self.ident_like(),
            '0'..='9' => self.numeric(),
            other if is_name_start(other) => self.ident_like(),
            _ => self.delim(),
        };
        Some(token)
    }

    /// Moves past every comment at the current place.
    fn skip_comments(&mut self) {
        while self.peek(0) == Some('/') && self.peek(1) == Some('*') {
            self.skip(2);
            self.skip_past_comment_end();
        }
    }

    /// Moves past the `*/` that ends a comment, or to the end.
    fn skip_past_comment_end(&mut self) {
        while let Some(current) = self.bump() {
            if current == '*' && self.peek(0) == Some('/') {
                self.skip(1);
                return;
            }
        }
    }

    /// One whitespace token for every space, tab and line end in a row.
    fn whitespace(&mut self) -> Token {
        self.skip_whitespace();
        Token::Whitespace
    }

    /// Moves past spaces, tabs and line ends.
    fn skip_whitespace(&mut self) {
        while matches!(self.peek(0), Some(' ' | '\t' | '\n')) {
            self.skip(1);
        }
    }

    /// `token`, moving past its one character.
    fn single(&mut self, token: Token) -> Token {
        self.skip(1);
        token
    }

    /// The current character as a token of its own.
    fn delim(&mut self) -> Token {
        self.bump().map_or(Token::Delim(REPLACEMENT), Token::Delim)
    }

    /// A string quoted by `quote`, or a bad string when a line ends it.
    fn string(&mut self, quote: char) -> Token {
        self.skip(1);
        loop {
            match self.bump() {
                None => return Token::Quoted,
                Some(current) if current == quote => return Token::Quoted,
                Some('\n') => {
                    self.at = self.at.saturating_sub(1);
                    return Token::BadString;
                }
                Some('\\') => self.skip_string_escape(),
                Some(_) => {}
            }
        }
    }

    /// Moves past what follows a `\` inside a string: an escaped line end
    /// or an escape.
    fn skip_string_escape(&mut self) {
        match self.peek(0) {
            None => {}
            Some('\n') => self.skip(1),
            Some(_) => {
                self.escaped();
            }
        }
    }

    /// `#` and a name, or a lone `#`.
    fn hash(&mut self) -> Token {
        self.skip(1);
        let named = self.peek(0).is_some_and(is_name) || valid_escape(self.peek(0), self.peek(1));
        if !named {
            return Token::Delim('#');
        }
        Token::Hash(self.name())
    }

    /// What a `-` starts: a number, `-->`, a name, or itself.
    fn minus(&mut self) -> Token {
        if self.starts_number() {
            return self.numeric();
        }
        if self.peek(1) == Some('-') && self.peek(2) == Some('>') {
            self.skip(3);
            return Token::Cdc;
        }
        if self.starts_ident() {
            return self.ident_like();
        }
        self.delim()
    }

    /// `<!--`, or a lone `<`.
    fn less_than(&mut self) -> Token {
        let opens = [1, 2, 3]
            .iter()
            .zip(['!', '-', '-'])
            .all(|(ahead, expected)| self.peek(*ahead) == Some(expected));
        if !opens {
            return self.delim();
        }
        self.skip(4);
        Token::Cdo
    }

    /// `@` and a name, or a lone `@`.
    fn at_keyword(&mut self) -> Token {
        self.skip(1);
        if !self.starts_ident() {
            return Token::Delim('@');
        }
        Token::AtKeyword(self.name())
    }

    /// A name, a function, or a `url(..)`.
    fn ident_like(&mut self) -> Token {
        let name = self.name();
        if self.peek(0) != Some('(') {
            return Token::Ident(name);
        }
        self.skip(1);
        if !name.eq_ignore_ascii_case("url") {
            return Token::Function(name);
        }
        self.skip_whitespace();
        if matches!(self.peek(0), Some('"' | '\'')) {
            return Token::Function(name);
        }
        self.url()
    }

    /// The rest of an unquoted `url(..)`.
    fn url(&mut self) -> Token {
        loop {
            match self.bump() {
                None | Some(')') => return Token::Url,
                Some(' ' | '\t' | '\n') => return self.url_end(),
                Some('"' | '\'' | '(') => return self.bad_url(),
                Some('\\') if valid_escape(Some('\\'), self.peek(0)) => {
                    self.escaped();
                }
                Some(current) if current == '\\' || is_non_printable(current) => {
                    return self.bad_url();
                }
                Some(_) => {}
            }
        }
    }

    /// The end of a `url(..)` after whitespace: its `)`, or a bad URL.
    fn url_end(&mut self) -> Token {
        self.skip_whitespace();
        match self.bump() {
            None | Some(')') => Token::Url,
            Some(_) => self.bad_url(),
        }
    }

    /// A bad URL, moving past what is left of it.
    fn bad_url(&mut self) -> Token {
        loop {
            match self.bump() {
                None | Some(')') => return Token::BadUrl,
                Some('\\') if valid_escape(Some('\\'), self.peek(0)) => {
                    self.escaped();
                }
                Some(_) => {}
            }
        }
    }

    /// A number and what follows it: a unit, `%`, or nothing.
    fn numeric(&mut self) -> Token {
        let number = self.number();
        if self.starts_ident() {
            return Token::Dimension(number, self.name());
        }
        if self.peek(0) == Some('%') {
            self.skip(1);
            return Token::Percentage(number);
        }
        Token::Number(number)
    }

    /// A number as written: its sign, digits, fraction and exponent.
    fn number(&mut self) -> String {
        let mut written = String::new();
        if let Some(sign @ ('+' | '-')) = self.peek(0) {
            self.skip(1);
            written.push(sign);
        }
        written.push_str(&self.digits());
        if self.peek(0) == Some('.') && self.peek(1).is_some_and(|c| c.is_ascii_digit()) {
            self.skip(1);
            written.push('.');
            written.push_str(&self.digits());
        }
        written.push_str(&self.exponent());
        written
    }

    /// An exponent such as `e3` or `E-2`, or nothing.
    fn exponent(&mut self) -> String {
        let signed = matches!(self.peek(1), Some('+' | '-'));
        let digit_at = if signed { 2 } else { 1 };
        let starts = matches!(self.peek(0), Some('e' | 'E'))
            && self.peek(digit_at).is_some_and(|c| c.is_ascii_digit());
        if !starts {
            return String::new();
        }
        let mut written = String::new();
        for _ in 0..digit_at {
            written.extend(self.bump());
        }
        written.push_str(&self.digits());
        written
    }

    /// The digits at the current place.
    fn digits(&mut self) -> String {
        let mut written = String::new();
        while let Some(digit) = self.peek(0).filter(char::is_ascii_digit) {
            self.skip(1);
            written.push(digit);
        }
        written
    }

    /// A name at the current place, its escapes decoded.
    fn name(&mut self) -> String {
        let mut name = String::new();
        loop {
            match self.peek(0) {
                Some(current) if is_name(current) => {
                    self.skip(1);
                    name.push(current);
                }
                Some('\\') if valid_escape(self.peek(0), self.peek(1)) => {
                    self.skip(1);
                    name.push(self.escaped());
                }
                Some(_) | None => return name,
            }
        }
    }

    /// The character an escape stands for, the `\` already passed.
    fn escaped(&mut self) -> char {
        let Some(first) = self.bump() else {
            return REPLACEMENT;
        };
        let Some(mut value) = first.to_digit(16) else {
            return first;
        };
        let mut digits: u8 = 1;
        while let Some(digit) = self
            .peek(0)
            .and_then(|c| c.to_digit(16))
            .filter(|_| digits < MOST_ESCAPE_DIGITS)
        {
            self.skip(1);
            value = value.saturating_mul(16).saturating_add(digit);
            digits = digits.saturating_add(1);
        }
        if matches!(self.peek(0), Some(' ' | '\t' | '\n')) {
            self.skip(1);
        }
        char::from_u32(value)
            .filter(|decoded| *decoded != '\0')
            .unwrap_or(REPLACEMENT)
    }

    /// Whether a name starts at the current place.
    fn starts_ident(&self) -> bool {
        match self.peek(0) {
            Some('-') => {
                self.peek(1).is_some_and(|c| is_name_start(c) || c == '-')
                    || valid_escape(self.peek(1), self.peek(2))
            }
            Some('\\') => valid_escape(self.peek(0), self.peek(1)),
            Some(current) => is_name_start(current),
            None => false,
        }
    }

    /// Whether a number starts at the current place.
    fn starts_number(&self) -> bool {
        let digit = |ahead: usize| self.peek(ahead).is_some_and(|c| c.is_ascii_digit());
        match self.peek(0) {
            Some('+' | '-') => digit(1) || (self.peek(1) == Some('.') && digit(2)),
            Some('.') => digit(1),
            Some(current) => current.is_ascii_digit(),
            None => false,
        }
    }
}

/// Whether `current` may start a name.
fn is_name_start(current: char) -> bool {
    current.is_ascii_alphabetic() || current == '_' || !current.is_ascii()
}

/// Whether `current` may be part of a name.
fn is_name(current: char) -> bool {
    is_name_start(current) || current.is_ascii_digit() || current == '-'
}

/// Whether `first` and `second` start an escape: a `\` not followed by a
/// line end.
fn valid_escape(first: Option<char>, second: Option<char>) -> bool {
    first == Some('\\') && second != Some('\n')
}

/// Whether `current` is a control character a URL may not hold.
fn is_non_printable(current: char) -> bool {
    matches!(current, '\u{0}'..='\u{8}' | '\u{b}' | '\u{e}'..='\u{1f}' | '\u{7f}')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(name: &str) -> Token {
        Token::Ident(name.to_owned())
    }

    /// A plain rule reads as names, punctuation and a dimension.
    #[test]
    fn a_plain_rule_reads_as_its_tokens() {
        let read = tokens(".a{color:red;padding:4px}");

        assert_eq!(
            read,
            [
                Token::Delim('.'),
                ident("a"),
                Token::OpenCurly,
                ident("color"),
                Token::Colon,
                ident("red"),
                Token::Semicolon,
                ident("padding"),
                Token::Colon,
                Token::Dimension("4".to_owned(), "px".to_owned()),
                Token::CloseCurly,
            ]
        );
    }

    /// Escaped names are decoded so an escaped URL becomes a URL token
    /// and an escaped colour name becomes its plain identifier.
    #[test]
    fn an_escaped_url_reads_as_a_url() {
        assert_eq!(tokens("\\75 rl(https://evil.test/x)"), [Token::Url]);
        assert_eq!(tokens("\\72 ed"), [ident("red")]);
    }

    /// Comments separate adjacent tokens rather than joining an import keyword;
    /// a trailing unclosed comment contributes no token.
    #[test]
    fn a_comment_splits_what_it_sits_in() {
        assert_eq!(
            tokens("@im/**/port"),
            [Token::AtKeyword("im".to_owned()), ident("port")]
        );
        assert_eq!(tokens("/* a */b/* c"), [ident("b")]);
    }

    /// A quoted `url("..")` reads as a function and a string, and a string
    /// broken by a line end reads as a bad one.
    #[test]
    fn quoted_urls_and_strings_read_whole() {
        assert_eq!(
            tokens("url( 'x' )"),
            [
                Token::Function("url".to_owned()),
                Token::Quoted,
                Token::Whitespace,
                Token::CloseParen
            ]
        );
        assert_eq!(
            tokens("'a\nb"),
            [Token::BadString, Token::Whitespace, ident("b")]
        );
    }

    /// Numbers keep their sign, fraction and exponent, and a `%` or unit
    /// after them.
    #[test]
    fn numbers_read_as_written() {
        assert_eq!(
            tokens("-1.5em 50% +3 2e3"),
            [
                Token::Dimension("-1.5".to_owned(), "em".to_owned()),
                Token::Whitespace,
                Token::Percentage("50".to_owned()),
                Token::Whitespace,
                Token::Number("+3".to_owned()),
                Token::Whitespace,
                Token::Number("2e3".to_owned()),
            ]
        );
    }

    /// An escape naming no character reads as the replacement character,
    /// never as a NUL.
    #[test]
    fn an_escape_of_nothing_reads_as_the_replacement() {
        assert_eq!(tokens("\\0 a"), [ident("\u{FFFD}a")]);
        assert_eq!(tokens("\\110000"), [ident("\u{FFFD}")]);
    }
}
