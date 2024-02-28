package tlv

import (
	"encoding/binary"
	"errors"
)

func ParseBER(data []byte) (TLV, error) {
	var err error
	var result TLV
	for len(data) > 0 {
		var tag Tag
		tag, data, err = parseBERTag(data)
		if err != nil {
			return result, err
		}

		var length int
		length, data, err = parseBERLength(data)
		if err != nil {
			return result, err
		}

		var value []byte
		value, data, err = parseValue(data, length)
		if err != nil {
			return result, err
		}
		result = append(result, Entry{
			Tag:    Tag(tag),
			Length: length,
			Value:  value,
		})
	}
	return result, nil
}

func ParseBERTL(data []byte) (TL, error) {
	var err error
	var result TL
	for len(data) > 0 {
		var tag Tag
		tag, data, err = parseBERTag(data)
		if err != nil {
			return result, err
		}

		var length int
		length, data, err = parseBERLength(data)
		if err != nil {
			return result, err
		}

		result = append(result, TLEntry{
			Tag:    Tag(tag),
			Length: length,
		})
	}
	return result, nil
}

func parseBERTag(data []byte) (tag Tag, remaining []byte, err error) {
	if len(data) == 0 {
		return 0, nil, errors.New("incomplete BER TLV: missing length")
	}

	b0 := data[0]
	data = data[1:]

	tagnum := int(b0)
	if b0&0b0001_1111 == 0b0001_1111 {
		for i := 0; i < 2; i++ {
			bN := data[0]
			data = data[1:]

			tagnum *= 256
			tagnum += int(bN)

			isLastByte := bN&0b1000_0000 == 0
			if isLastByte {
				break
			}
		}
	}

	tag = Tag(tagnum)
	return tag, data, nil
}

func parseBERLength(data []byte) (b0 int, remaining []byte, err error) {
	if len(data) == 0 {
		return 0, nil, errors.New("incomplete BER TLV: missing length")
	}

	b0 = int(data[0])
	data = data[1:]
	if b0 < 0x80 {
		return b0, data, nil
	}

	if b0 == 0x80 || b0 >= 0x85 {
		return 0, nil, errors.New("incomplete BER TLV: first byte of the length is invalid")
	}
	howmany := b0 & 0x0F
	lenBytes := append(make([]byte, 8-howmany), data[:howmany]...)
	data = data[howmany:]

	return int(binary.BigEndian.Uint64(lenBytes)), data, nil
}

func parseValue(data []byte, length int) (value []byte, remaining []byte, err error) {
	if len(data) < length {
		return nil, nil, errors.New("incomplete BER TLV: expected length is bigger than the length of the remaining data")
	}

	value = data[:length]
	data = data[length:]

	return value, data, nil
}
