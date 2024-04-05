package tlv

type (
	TL      []TLEntry
	TLEntry struct {
		Tag    Tag
		Length int
	}
)
