package tlv

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type Tag uint32

func (tag Tag) String() string {
	if tag > 0xFF {
		return fmt.Sprintf("%04X", uint16(tag))
	}
	return fmt.Sprintf("%02X", uint8(tag))
}

func (tag Tag) Encode() ([]byte, error) {
	var result [3]byte
	var count int
	for tag > 0 {
		if count > 2 {
			return nil, errors.New("tag is too big to be encoded")
		}
		result[2-count] = byte(tag % 256)
		tag /= 256
		count++
	}
	return result[3-count:], nil
}

type tlvTagEncoder struct{}

func TagEncoder() EncoderDecoder[Tag] {
	return tlvTagEncoder{}
}

func (d tlvTagEncoder) Decode(tag *Tag, data []byte) (int, error) {
	// If right-most 5 bits are 1 then consider that the tag has more than one byte
	if data[0]&0b0001_1111 != 0b0001_1111 {
		*tag = Tag(data[0])
		return 1, nil
	}

	if len(data) < 2 {
		return 0, newTLVDecodeError(ErrTagShouldHave2Bytes, "expecting at least 2 bytes")
	}

	// If left-most 3 bytes are 0 then consider it is the last byte
	for data[1]&0b1110_0000 != 0b1110_0000 {
		*tag = Tag(binary.BigEndian.Uint16(data))
		return 2, nil
	}

	return 0, newTLVDecodeError(ErrTagTooLong, "second byte of tag is not final, but VisaNet supports at most 2 bytes")
}

func (d tlvTagEncoder) Encode(tag Tag) ([]byte, error) {
	return tag.Encode()
}
