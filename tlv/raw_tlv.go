package tlv

// type rawTlvEncoder struct {
// 	tagEncoder    encoding.EncoderDecoder[Tag]
// 	lengthEncoder encoding.EncoderDecoder[Length]
// }

// func RawTLV() encoding.EncoderDecoder[Map] {
// 	return rawTlvEncoder{
// 		tagEncoder:    TagEncoder(),
// 		lengthEncoder: LengthEncoder(),
// 	}
// }

// func (e rawTlvEncoder) Decode(m *Map, data []byte) (int, error) {
// 	if m == nil || *m == nil {
// 		*m = make(Map)
// 	}

// 	var totalRead int
// 	nonPointerMap := *m
// 	for len(data) > 0 {
// 		var tag Tag
// 		read, err := e.tagEncoder.Decode(&tag, data)
// 		totalRead += read
// 		if err != nil {
// 			return totalRead, errors.WithMessage(err, "could not decode TLV tag")
// 		}
// 		data = data[read:]

// 		var length Length
// 		read, err = e.lengthEncoder.Decode(&length, data)
// 		totalRead += read
// 		if err != nil {
// 			return totalRead, errors.WithMessagef(err, "could not decode TLV length for tag %2X", tag)
// 		}
// 		data = data[read:]

// 		if len(data) < int(length) {
// 			return totalRead, newTLVDecodeErrorf(ErrValueTooShort, "could not read TLV tag %2X: expecting %d bytes but only found %d", tag, length, len(data))
// 		}
// 		value := data[:length]
// 		data = data[length:]
// 		totalRead += int(length)

// 		nonPointerMap[Tag(tag)] = value
// 	}
// 	(*m) = nonPointerMap
// 	return totalRead, nil
// }

// func (d rawTlvEncoder) Encode(state Map) ([]byte, error) {
// 	return nil, errors.New("TODO: not implemented (tlv)")
// }

// func RawTLVEncoder[T any](subEncoders map[Tag]encoding.EncoderDecoder[T]) encoding.EncoderDecoder[T] {
// 	return utils.MapRouter("Tag", RawTLV(), subEncoders)
// }
