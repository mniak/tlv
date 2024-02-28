package encoding

type Encoder[T any] interface {
	Encode(state T) ([]byte, error)
}

// Decoder
// Returns the total of bytes read and an error if present
type Decoder[T any] interface {
	Decode(state *T, data []byte) (int, error)
}

type EncoderDecoder[T any] interface {
	Encoder[T]
	Decoder[T]
}
