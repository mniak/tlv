package tlv

type Value []byte

func (val Value) AsBERTLV() (TLV, error) {
	return ParseBER(val)
}
