package redact

import "bytes"

type keyKind int

const (
	keyPlain keyKind = iota
	keySecret
	keyPhone
)

// appendJSON redacts a line that is known to be valid JSON. A value whose key
// names a secret is replaced whole, a value whose key names a phone number has
// its digits masked, and every other string value goes through the free-text
// rules. Only complete value tokens are replaced, and only with JSON strings,
// so the output is still valid JSON.
//
// The walker does not track the grammar. Inside a valid document, a string
// followed by ':' is a key and every other string is a value, which is all it
// needs to know.
func (r *Redactor) appendJSON(dst, src []byte, slow bool) []byte {
	for i := 0; i < len(src); {
		q := bytes.IndexByte(src[i:], '"')
		if q < 0 {
			return append(dst, src[i:]...)
		}
		dst = append(dst, src[i:i+q]...)
		i += q
		end := stringEnd(src, i)
		colon := skipSpace(src, end)
		if colon < len(src) && src[colon] == ':' {
			kind := r.keyKind(src[i+1 : end-1])
			dst = append(dst, src[i:colon+1]...)
			i = colon + 1
			if kind == keyPlain {
				continue
			}
			v := skipSpace(src, i)
			dst = append(dst, src[i:v]...)
			i = v
			if v >= len(src) || (kind == keyPhone && (src[v] == '{' || src[v] == '[')) {
				continue // walk into the object or array; its keys are checked one by one
			}
			vend := valueEnd(src, v)
			dst = r.appendSensitive(dst, src[v:vend], kind)
			i = vend
			continue
		}
		dst = append(dst, '"')
		dst = r.appendString(dst, src[i+1:end-1], slow)
		dst = append(dst, '"')
		i = end
	}
	return dst
}

// appendString redacts the raw (still escaped) contents of a JSON string value.
// The free-text rules never rewrite a backslash or a quote, so escapes survive.
func (r *Redactor) appendString(dst, raw []byte, slow bool) []byte {
	if !slow && !r.mayContain(raw) {
		return append(dst, raw...)
	}
	return r.appendText(dst, raw)
}

// appendSensitive rewrites the value of a secret or phone key. null, true and
// false carry no secret and are kept, as is an empty string.
func (r *Redactor) appendSensitive(dst, val []byte, kind keyKind) []byte {
	switch {
	case val[0] == 'n' || val[0] == 't' || val[0] == 'f' || string(val) == `""`:
		return append(dst, val...)
	case kind == keySecret:
		// Strings, numbers, and whole objects or arrays under a secret key.
		return append(append(append(dst, '"'), Mask...), '"')
	case val[0] == '"':
		dst = append(dst, '"')
		dst = r.appendMaskedDigits(dst, val[1:len(val)-1])
		return append(dst, '"')
	default:
		// A number becomes a string: "6591234567" is not a valid number once masked.
		dst = append(dst, '"')
		dst = r.appendMaskedDigits(dst, val)
		return append(dst, '"')
	}
}

func (r *Redactor) keyKind(rawKey []byte) keyKind {
	var stack [128]byte
	lower := foldLower(stack[:0], rawKey)
	switch {
	case containsAny(lower, r.secretKeys):
		return keySecret
	case containsAny(lower, r.phoneKeys):
		return keyPhone
	default:
		return keyPlain
	}
}

// stringEnd returns the index just past the string that opens at src[i].
func stringEnd(src []byte, i int) int {
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return len(src)
}

// valueEnd returns the index just past the value that starts at src[i].
func valueEnd(src []byte, i int) int {
	switch src[i] {
	case '"':
		return stringEnd(src, i)
	case '{', '[':
		depth := 0
		for j := i; j < len(src); j++ {
			switch src[j] {
			case '"':
				j = stringEnd(src, j) - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1
				}
			}
		}
		return len(src)
	default:
		j := i
		for j < len(src) && !isDelim(src[j]) {
			j++
		}
		return j
	}
}

func isDelim(c byte) bool {
	switch c {
	case ',', '}', ']', ' ', '\t', '\r', '\n':
		return true
	}
	return false
}

func skipSpace(src []byte, i int) int {
	for i < len(src) && (src[i] == ' ' || src[i] == '\t' || src[i] == '\r' || src[i] == '\n') {
		i++
	}
	return i
}
