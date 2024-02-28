package tlv

import (
	"fmt"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTag_Examples(t *testing.T) {
	t.Run("Single byte", func(t *testing.T) {
		for fakeTag := byte(0); fakeTag <= 30; fakeTag++ {
			t.Run(fmt.Sprintf("0x%2X", fakeTag), func(t *testing.T) {
				fakeRemaining := []byte(gofakeit.SentenceSimple())
				input := append([]byte{fakeTag}, fakeRemaining...)

				tag, remaining, err := parseBERTag(input)
				require.NoError(t, err)

				assert.Equal(t, int(fakeTag), int(tag))
				assert.Equal(t, fakeRemaining, remaining)
			})
		}
	})

	t.Run("Two bytes", func(t *testing.T) {
		for _, fakeByte1 := range []byte{0x1F, 0x3F, 0x5F, 0x9F} {
			for fakeByte2 := byte(0x00); fakeByte2 <= 0x7F; fakeByte2 += 4 {
				t.Run(fmt.Sprintf("0x%2X%2X", fakeByte1, fakeByte2), func(t *testing.T) {
					fakeTag := int(fakeByte1)*256 + int(fakeByte2)
					fakeRemaining := []byte(gofakeit.SentenceSimple())
					input := append([]byte{fakeByte1, fakeByte2}, fakeRemaining...)

					tag, remaining, err := parseBERTag(input)
					require.NoError(t, err)

					assert.Equal(t, int(fakeTag), int(tag))
					assert.Equal(t, fakeRemaining, remaining)
				})
			}
		}
	})

	t.Run("Three bytes", func(t *testing.T) {
		for _, fakeByte1 := range []byte{0x1F, 0x3F, 0x5F, 0x9F} {
			for _, fakeByte2 := range []byte{0x80, 0x81, 0x82, 0x84, 0x88, 0x8F, 0x9F, 0xAF, 0xCF} {
				for fakeByte3 := byte(0x00); fakeByte3 <= 0x7F; fakeByte3 += 10 {
					t.Run(fmt.Sprintf("0x%2X%2X%2X", fakeByte1, fakeByte2, fakeByte3), func(t *testing.T) {
						fakeTag := (int(fakeByte1)*256+int(fakeByte2))*256 + int(fakeByte3)
						fakeRemaining := []byte(gofakeit.SentenceSimple())
						input := append([]byte{fakeByte1, fakeByte2, fakeByte3}, fakeRemaining...)

						tag, remaining, err := parseBERTag(input)
						require.NoError(t, err)

						assert.Equal(t, int(fakeTag), int(tag))
						assert.Equal(t, fakeRemaining, remaining)
					})
				}
			}
		}
	})
}

func TestParseLength_Examples(t *testing.T) {
	t.Run("Single byte", func(t *testing.T) {
		for fakeLength := byte(0x00); fakeLength <= 0x7F; fakeLength++ {
			t.Run(fmt.Sprintf("0x%2X", fakeLength), func(t *testing.T) {
				fakeRemaining := []byte(gofakeit.SentenceSimple())
				input := append([]byte{fakeLength}, fakeRemaining...)

				length, remaining, err := parseBERLength(input)
				require.NoError(t, err)

				assert.Equal(t, int(fakeLength), int(length))
				assert.Equal(t, fakeRemaining, remaining)
			})
		}
	})
	t.Run("Bounds check", func(t *testing.T) {
		testCases := []struct {
			bytes  []byte
			length int64
		}{
			// Single byte bounds
			{
				bytes:  []byte{0x00},
				length: 0,
			},
			{
				bytes:  []byte{0x7F},
				length: 127,
			},
			// 2 bytes bounds
			{
				bytes:  []byte{0x81, 0x00},
				length: 0,
			},
			{
				bytes:  []byte{0x81, 0xFF},
				length: 255,
			},
			// 3 bytes bounds
			{
				bytes:  []byte{0x82, 0x00, 0x00},
				length: 0,
			},
			{
				bytes:  []byte{0x82, 0xFF, 0xFF},
				length: 65535,
			},
			// 4 bytes bounds
			{
				bytes:  []byte{0x83, 0x00, 0x00, 0x00},
				length: 0,
			},
			{
				bytes:  []byte{0x83, 0xFF, 0xFF, 0xFF},
				length: 16777215,
			},
			// 5 bytes bounds
			{
				bytes:  []byte{0x84, 0x00, 0x00, 0x00, 0x00},
				length: 0,
			},
			{
				bytes:  []byte{0x84, 0xFF, 0xFF, 0xFF, 0xFF},
				length: 4294967295,
			},
		}
		for _, tc := range testCases {
			t.Run(fmt.Sprintf("%2X", tc.bytes), func(t *testing.T) {
				fakeRemaining := []byte(gofakeit.SentenceSimple())
				input := append(tc.bytes, fakeRemaining...)

				length, remaining, err := parseBERLength(input)
				require.NoError(t, err)

				assert.Equal(t, int64(tc.length), int64(length))
				assert.Equal(t, fakeRemaining, remaining)
			})
		}
	})
}
