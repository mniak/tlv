package tlv

import "fmt"

type Value []byte

func (val Value) AsBERTLV() (TLV, error) {
	return ParseBER(val)
}

func (val Value) Hex() string {
	if len(val) == 0 {
		return ""
	}
	return fmt.Sprintf("%2X", val)
}
