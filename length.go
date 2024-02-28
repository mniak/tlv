package tlv

import (
	"encoding/binary"
	"errors"
)

// type Length uint

// type tlvLengthEncoder struct{}

// func LengthEncoder() encoding.EncoderDecoder[Length] {
// 	return tlvLengthEncoder{}
// }

// func (d tlvLengthEncoder) Decode(state *Length, data []byte) (int, error) {
// 	if len(data) == 0 {
// 		return 0, newTLVDecodeError(ErrLengthHasNoBytes, "no bytes found")
// 	}

// 	// If left-most 1 bit is 0, then it is the Short Form, one single byte
// 	if data[0]&0b1000_0000 == 0 {
// 		*state = Length(data[0])
// 		return 1, nil
// 	}

// 	howMuchMore := data[0] & 0b0111_1111
// 	switch howMuchMore {
// 	case 1:
// 		if len(data) < 2 {
// 			return 0, newTLVDecodeError(ErrLengthFormatError, "expecting at least 2 bytes")
// 		}
// 		*state = Length(data[1])
// 		return 2, nil
// 	case 2:
// 		if len(data) < 3 {
// 			return 0, newTLVDecodeError(ErrLengthFormatError, "expecting at least 3 bytes")
// 		}
// 		*state = Length(binary.BigEndian.Uint16(data[1:]))
// 		return 3, nil
// 	default:
// 		return 0, newTLVDecodeErrorf(ErrLengthFormatError, "the length field should have at most 3 bytes but it appears to have %d", 1+howMuchMore)
// 	}
// }

// func (d tlvLengthEncoder) Encode(state Length) ([]byte, error) {
// 	if state < 128 {
// 		return []byte{byte(state)}, nil
// 	}

// 	var result [9]byte
// 	var count int
// 	for state > 0 {
// 		result[8-count] = byte(state % 256)
// 		state /= 256
// 		count++
// 	}
// 	result[8-count] = byte(0x80 + count)
// 	return result[8-count:], nil
// }

type LengthEncoder interface {
	Encode(length int) (lengthBytes []byte, err error)
	Decode(dataWithLength []byte) (length int, data []byte, err error)
}

var (
	ErrDataLengthTooBigForEncoder = errors.New("data length is too big for this encoder")
	ErrDataTooShortForDecoder     = errors.New("data is too short for this decoder")
	ErrDataShorterThanLength      = errors.New("data is shorter than the length field")
)

var (
	ShortLengthEncoder    _ShortLengthEncoder
	ExtendedLengthEncoder _ExtendedLengthEncoder
)

type _ShortLengthEncoder struct{}

const _ShortLengthEncoder_MaxLength = 256

func (le _ShortLengthEncoder) Encode(length int) (lengthBytes []byte, err error) {
	if length == 0 {
		return []byte{0x00}, nil
	}
	if length > _ShortLengthEncoder_MaxLength {
		return nil, ErrDataLengthTooBigForEncoder
	}

	if length == _ShortLengthEncoder_MaxLength {
		return []byte{0x00}, nil
	}

	return []byte{byte(length)}, nil
}

func (le _ShortLengthEncoder) Decode(rawdata []byte) (length int, data []byte, err error) {
	if len(rawdata) < 1 {
		return 0, nil, ErrDataTooShortForDecoder
	}

	lengthByte := rawdata[0]
	rawdata = rawdata[1:]

	length = int(lengthByte)
	if length == 0 {
		length = _ShortLengthEncoder_MaxLength
	}

	if len(rawdata) < length {
		return length, nil, ErrDataShorterThanLength
	}

	return length, rawdata[:length], nil
}

type _ExtendedLengthEncoder struct{}

const _ExtendedLengthEncoder_MaxLength = 256 * 256

func (le _ExtendedLengthEncoder) Encode(length int) (lengthBytes []byte, err error) {
	if length > _ExtendedLengthEncoder_MaxLength {
		return nil, ErrDataLengthTooBigForEncoder
	}

	if length == _ExtendedLengthEncoder_MaxLength {
		return []byte{0, 0, 0}, nil
	}

	binary.BigEndian.AppendUint16([]byte{0}, uint16(length))
	return lengthBytes, nil
}

func (le _ExtendedLengthEncoder) Decode(rawdata []byte) (length int, data []byte, err error) {
	if len(rawdata) < 2 {
		return 0, nil, ErrDataTooShortForDecoder
	}

	length = int(binary.BigEndian.Uint16(rawdata))
	rawdata = rawdata[2:]
	if length == 0 {
		length = _ExtendedLengthEncoder_MaxLength
	}

	if len(rawdata) < length {
		return length, nil, ErrDataShorterThanLength
	}

	return length, rawdata[:length], nil
}
